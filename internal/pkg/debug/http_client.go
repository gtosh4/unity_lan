package debug

import (
	"bytes"
	"io"
	"net/http"

	"go.uber.org/zap"
)

type LogRoundTrip struct {
	Base http.RoundTripper
	Log  *zap.SugaredLogger
}

func (rt *LogRoundTrip) RoundTrip(req *http.Request) (*http.Response, error) {
	log := rt.Log.With(zap.String("method", req.Method), zap.String("url", req.URL.String()))
	log.Infof("Request params: %+v", req.URL.Query())
	log.Infof("Request headers: %+v", req.Header)

	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(req.Body); err != nil {
		return nil, err
	}
	log.Infof("Request body: %s", buf)
	req.Body = io.NopCloser(buf)

	resp, err := rt.Base.RoundTrip(req)
	if err != nil {
		log.Errorf("Got error: %v", err)
	} else {
		log.Infof("Got response %s", resp.Status)
	}
	if resp.Body != nil {
		buf.Reset()
		if _, err := buf.ReadFrom(resp.Body); err != nil {
			log.Warnf("ignoring body read err: %v", err)
		} else {
			log.Infof("Response body: %s", buf)
		}
		resp.Body.Close()
		resp.Body = io.NopCloser(buf)
	}
	return resp, err
}
