package content

import (
	"io"
	"sync"

	eventstypes "github.com/containerd/containerd/api/events"
	api "github.com/containerd/containerd/api/services/content/v1"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/events"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/metadata"
	"github.com/containerd/containerd/plugin"
	ptypes "github.com/gogo/protobuf/types"
	digest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type service struct {
	store     content.Store
	publisher events.Publisher
}

var bufPool = sync.Pool{
	New: func() interface{} {
		buffer := make([]byte, 1<<20)
		return &buffer
	},
}

var _ api.ContentServer = &service{}

func init() {
	plugin.Register(&plugin.Registration{
		Type: plugin.GRPCPlugin,
		ID:   "content",
		Requires: []plugin.Type{
			plugin.MetadataPlugin,
		},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			m, err := ic.Get(plugin.MetadataPlugin)
			if err != nil {
				return nil, err
			}

			s, err := NewService(m.(*metadata.DB).ContentStore(), ic.Events)
			return s, err
		},
	})
}

// NewService returns the content GRPC server
func NewService(cs content.Store, publisher events.Publisher) (api.ContentServer, error) {
	return &service{
		store:     cs,
		publisher: publisher,
	}, nil
}

func (s *service) Register(server *grpc.Server) error {
	api.RegisterContentServer(server, s)
	return nil
}

func (s *service) Info(ctx context.Context, req *api.InfoRequest) (*api.InfoResponse, error) {
	if err := req.Digest.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%q failed validation", req.Digest)
	}

	bi, err := s.store.Info(ctx, req.Digest)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}

	return &api.InfoResponse{
		Info: infoToGRPC(bi),
	}, nil
}

func (s *service) Update(ctx context.Context, req *api.UpdateRequest) (*api.UpdateResponse, error) {
	if err := req.Info.Digest.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%q failed validation", req.Info.Digest)
	}

	info, err := s.store.Update(ctx, infoFromGRPC(req.Info), req.UpdateMask.GetPaths()...)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}

	return &api.UpdateResponse{
		Info: infoToGRPC(info),
	}, nil
}

func (s *service) List(req *api.ListContentRequest, session api.Content_ListServer) error {
	var (
		buffer    []api.Info
		sendBlock = func(block []api.Info) error {
			// send last block
			return session.Send(&api.ListContentResponse{
				Info: block,
			})
		}
	)

	if err := s.store.Walk(session.Context(), func(info content.Info) error {
		buffer = append(buffer, api.Info{
			Digest:    info.Digest,
			Size_:     info.Size,
			CreatedAt: info.CreatedAt,
			Labels:    info.Labels,
		})

		if len(buffer) >= 100 {
			if err := sendBlock(buffer); err != nil {
				return err
			}

			buffer = buffer[:0]
		}

		return nil
	}, req.Filters...); err != nil {
		return err
	}

	if len(buffer) > 0 {
		// send last block
		if err := sendBlock(buffer); err != nil {
			return err
		}
	}

	return nil
}

func (s *service) Delete(ctx context.Context, req *api.DeleteContentRequest) (*ptypes.Empty, error) {
	log.G(ctx).WithField("digest", req.Digest).Debugf("delete content")
	if err := req.Digest.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}

	if err := s.store.Delete(ctx, req.Digest); err != nil {
		return nil, errdefs.ToGRPC(err)
	}

	if err := s.publisher.Publish(ctx, "/content/delete", &eventstypes.ContentDelete{
		Digest: req.Digest,
	}); err != nil {
		return nil, err
	}

	return &ptypes.Empty{}, nil
}

func (s *service) Read(req *api.ReadContentRequest, session api.Content_ReadServer) error {
	if err := req.Digest.Validate(); err != nil {
		return status.Errorf(codes.InvalidArgument, "%v: %v", req.Digest, err)
	}

	oi, err := s.store.Info(session.Context(), req.Digest)
	if err != nil {
		return errdefs.ToGRPC(err)
	}

	ra, err := s.store.ReaderAt(session.Context(), req.Digest)
	if err != nil {
		return errdefs.ToGRPC(err)
	}
	defer ra.Close()

	var (
		offset = req.Offset
		size   = req.Size_

		// TODO(stevvooe): Using the global buffer pool. At 32KB, it is probably
		// little inefficient for work over a fast network. We can tune this later.
		p = bufPool.Get().(*[]byte)
	)
	defer bufPool.Put(p)

	if offset < 0 {
		offset = 0
	}

	if size <= 0 {
		size = oi.Size - offset
	}

	if offset+size > oi.Size {
		return status.Errorf(codes.OutOfRange, "read past object length %v bytes", oi.Size)
	}

	_, err = io.CopyBuffer(
		&readResponseWriter{session: session},
		io.NewSectionReader(ra, offset, size), *p)
	return err
}

// readResponseWriter is a writer that places the output into ReadContentRequest messages.
//
// This allows io.CopyBuffer to do the heavy lifting of chunking the responses
// into the buffer size.
type readResponseWriter struct {
	offset  int64
	session api.Content_ReadServer
}

func (rw *readResponseWriter) Write(p []byte) (n int, err error) {
	if err := rw.session.Send(&api.ReadContentResponse{
		Offset: rw.offset,
		Data:   p,
	}); err != nil {
		return 0, err
	}

	rw.offset += int64(len(p))
	return len(p), nil
}

func (s *service) Status(ctx context.Context, req *api.StatusRequest) (*api.StatusResponse, error) {
	status, err := s.store.Status(ctx, req.Ref)
	if err != nil {
		return nil, errdefs.ToGRPCf(err, "could not get status for ref %q", req.Ref)
	}

	var resp api.StatusResponse
	resp.Status = &api.Status{
		StartedAt: status.StartedAt,
		UpdatedAt: status.UpdatedAt,
		Ref:       status.Ref,
		Offset:    status.Offset,
		Total:     status.Total,
		Expected:  status.Expected,
	}

	return &resp, nil
}

func (s *service) ListStatuses(ctx context.Context, req *api.ListStatusesRequest) (*api.ListStatusesResponse, error) {
	statuses, err := s.store.ListStatuses(ctx, req.Filters...)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}

	var resp api.ListStatusesResponse
	for _, status := range statuses {
		resp.Statuses = append(resp.Statuses, api.Status{
			StartedAt: status.StartedAt,
			UpdatedAt: status.UpdatedAt,
			Ref:       status.Ref,
			Offset:    status.Offset,
			Total:     status.Total,
			Expected:  status.Expected,
		})
	}

	return &resp, nil
}

func (s *service) Write(session api.Content_WriteServer) (err error) {
	var (
		ctx = session.Context()
		msg api.WriteContentResponse
	)

	defer func(msg *api.WriteContentResponse) {
		// pump through the last message if no error was encountered
		if err != nil {
			if s, ok := status.FromError(err); ok && s.Code() != codes.AlreadyExists {
				// TODO(stevvooe): Really need a log line here to track which
				// errors are actually causing failure on the server side. May want
				// to configure the service with an interceptor to make this work
				// identically across all GRPC methods.
				//
				// This is pretty noisy, so we can remove it but leave it for now.
				log.G(ctx).WithError(err).Error("(*service).Write failed")
			}

			return
		}

		err = session.Send(msg)
	}(&msg)

	// handle the very first request!
	req, err := session.Recv()
	if err != nil {
		return err
	}
	if req.Ref == "" {
		return status.Errorf(codes.InvalidArgument, "first message must have a reference")
	}

	ctx = contextForWriteRequest(ctx, req)
	log.G(ctx).Debug("(*service).Write started")
	// this action locks the writer for the session.
	wr, err := s.store.Writer(ctx, req.Ref, req.Total, req.Expected)
	if err != nil {
		return errdefs.ToGRPC(err)
	}
	defer wr.Close()

	blobExistsInStore := func(blob digest.Digest) error {
		if blob == "" {
			return nil
		}
		if _, err := s.store.Info(session.Context(), blob); err != nil {
			return nil
		}
		if err := s.store.Abort(session.Context(), req.Ref); err != nil {
			log.G(ctx).WithError(err).Error("failed to abort write")
		}
		return status.Errorf(codes.AlreadyExists, "blob with expected digest %v exists", req.Expected)
	}

	progress := &progress{}
	for {
		if err := progress.updateReq(req); err != nil {
			return err
		}
		if err := blobExistsInStore(req.Expected); err != nil {
			return err
		}

		msg, err = handleWriteRequestAction(wr, *progress)
		if err != nil {
			return err
		}

		if req.Action == api.WriteActionCommit {
			if err := commit(ctx, wr, *progress); err != nil {
				return err
			}
		}

		msg.Digest = wr.Digest()
		if err := session.Send(&msg); err != nil {
			return err
		}

		req, err = session.Recv()
		switch {
		case err == io.EOF:
			return nil
		case err != nil:
			return err
		}
	}
}

func contextForWriteRequest(ctx context.Context, req *api.WriteContentRequest) context.Context {
	fields := logrus.Fields{"ref": req.Ref}

	if total := req.Total; total > 0 {
		fields["total"] = total
	}
	if expected := req.Expected; expected != "" {
		fields["expected"] = expected
	}

	return log.WithLogger(ctx, log.G(ctx).WithFields(fields))
}

type progress struct {
	total       int64
	expected    digest.Digest
	lastRequest *api.WriteContentRequest
}

func (p *progress) updateReq(req *api.WriteContentRequest) error {
	p.lastRequest = req
	if err := p.validateExpected(req.Expected); err != nil {
		return err
	}
	return p.updateTotal(req.Total)
}

func (p *progress) validateExpected(reqExpected digest.Digest) error {
	// NOTE(stevvooe): In general, there are two cases underwhich a remote
	// writer is used.
	//
	// For pull, we almost always have this before fetching large content,
	// through descriptors. We allow predeclaration of the expected size
	// and digest.
	//
	// For push, it is more complex. If we want to cut through content into
	// storage, we may have no expectation until we are done processing the
	// content. The case here is the following:
	//
	// 	1. Start writing content.
	// 	2. Compress inline.
	// 	3. Validate digest and size (maybe).
	//
	// Supporting these two paths is quite awkward but it lets both API
	// users use the same writer style for each with a minimum of overhead.
	if reqExpected == "" {
		return nil
	}
	if p.expected != "" && p.expected != reqExpected {
		return status.Errorf(codes.InvalidArgument, "inconsistent digest provided: %v != %v", reqExpected, p.expected)
	}
	p.expected = reqExpected
	return nil
}

func (p *progress) updateTotal(reqTotal int64) error {
	if reqTotal > 0 {
		// Update the expected total. Typically, this could be seen at
		// negotiation time or on a commit message.
		if p.total > 0 && reqTotal != p.total {
			return status.Errorf(codes.InvalidArgument, "inconsistent total provided: %v != %v", reqTotal, p.total)
		}
		p.total = reqTotal
	}
	return nil
}

func handleWriteRequestAction(wr content.Writer, progress progress) (api.WriteContentResponse, error) {
	req := progress.lastRequest
	ws, err := wr.Status()
	if err != nil {
		return api.WriteContentResponse{}, errdefs.ToGRPC(err)
	}

	msg := api.WriteContentResponse{
		Action: req.Action,
		Offset: ws.Offset, // always set the offset.
	}

	switch req.Action {
	case api.WriteActionStat:
		msg.StartedAt = ws.StartedAt
		msg.UpdatedAt = ws.UpdatedAt
		msg.Total = progress.total

	case api.WriteActionWrite, api.WriteActionCommit:
		if req.Offset > 0 {
			// validate the offset if provided
			if req.Offset != ws.Offset {
				return msg, status.Errorf(codes.OutOfRange, "write @%v must occur at current offset %v", req.Offset, ws.Offset)
			}
		}

		if req.Offset == 0 && ws.Offset > 0 {
			if err := wr.Truncate(req.Offset); err != nil {
				return msg, errors.Wrapf(err, "truncate failed")
			}
			msg.Offset = req.Offset
		}

		// issue the write if we actually have data.
		if len(req.Data) > 0 {
			// While this looks like we could use io.WriterAt here, because we
			// maintain the offset as append only, we just issue the write.
			n, err := wr.Write(req.Data)
			if err != nil {
				return msg, err
			}

			if n != len(req.Data) {
				// TODO(stevvooe): Perhaps, we can recover this by including it
				// in the offset on the write return.
				return msg, status.Errorf(codes.DataLoss, "wrote %v of %v bytes", n, len(req.Data))
			}

			msg.Offset += int64(n)
		}
	}
	return msg, nil
}

func commit(ctx context.Context, wr content.Writer, progress progress) error {
	var opts []content.Opt
	if progress.lastRequest.Labels != nil {
		opts = append(opts, content.WithLabels(progress.lastRequest.Labels))
	}
	return wr.Commit(ctx, progress.total, progress.expected, opts...)
}

func (s *service) Abort(ctx context.Context, req *api.AbortRequest) (*ptypes.Empty, error) {
	if err := s.store.Abort(ctx, req.Ref); err != nil {
		return nil, errdefs.ToGRPC(err)
	}

	return &ptypes.Empty{}, nil
}

func infoToGRPC(info content.Info) api.Info {
	return api.Info{
		Digest:    info.Digest,
		Size_:     info.Size,
		CreatedAt: info.CreatedAt,
		UpdatedAt: info.UpdatedAt,
		Labels:    info.Labels,
	}
}

func infoFromGRPC(info api.Info) content.Info {
	return content.Info{
		Digest:    info.Digest,
		Size:      info.Size_,
		CreatedAt: info.CreatedAt,
		UpdatedAt: info.UpdatedAt,
		Labels:    info.Labels,
	}
}
