package server

import (
	"context"
	"net"
	"strconv"

	unitylanv1 "github.com/gtosh4/unity_lan/gen/proto/go/unitylan/v1"
	"google.golang.org/grpc/peer"
)

func addrToApi(addr net.Addr) (*unitylanv1.Address, error) {
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, err
	}

	portI, err := strconv.ParseUint(port, 10, 64)
	if err != nil {
		return nil, err
	}

	return &unitylanv1.Address{
		Ip:   net.ParseIP(host),
		Port: portI,
	}, nil
}

func (srv *Server) Connect(ctx context.Context, req *unitylanv1.ConnectRequest) (*unitylanv1.ConnectResponse, error) {
	resp := &unitylanv1.ConnectResponse{}

	p, ok := peer.FromContext(ctx)
	if ok {
		addr, err := addrToApi(p.Addr)
		if err != nil {
			srv.ctx.Warnf("Could not convert addr to api type: %v", err)
		} else {
			resp.Source = addr
		}
	}

	ip, err := srv.ipam.AcquireIP(srv.prefix.Cidr)
	if err != nil {
		return nil, err
	}

	resp.Address = ip.IP.IPAddr().IP

	return resp, nil
}

func (srv *Server) Heartbeat(ctx context.Context, req *unitylanv1.HeartbeatRequest) (*unitylanv1.HeartbeatResponse, error) {
	p, ok := peer.FromContext(ctx)
	if ok {
		srv.Log().Infof("Heartbeat from %s/%s", p.Addr.Network(), p.Addr)
	}
	return &unitylanv1.HeartbeatResponse{}, nil
}
