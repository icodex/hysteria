package auth

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFetchPanelJSONETag(t *testing.T) {
	var requests atomic.Int32
	var sawINM atomic.Pointer[string]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inm := r.Header.Get("If-None-Match")
		sawINM.Store(&inm)
		requests.Add(1)
		if requests.Load() == 1 {
			w.Header().Set("ETag", `"etag-v1"`)
			_, _ = w.Write([]byte(`{"users":[{"id":1,"uuid":"u1"}]}`))
			return
		}
		// 第二次请求带 If-None-Match，命中 304
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	var out ResponseData
	unchanged, err := FetchPanelJSON(srv.URL, &out)
	assert.NoError(t, err)
	assert.False(t, unchanged)
	assert.Equal(t, []User{{ID: 1, UUID: "u1"}}, out.Users)

	unchanged, err = FetchPanelJSON(srv.URL, &out)
	assert.NoError(t, err)
	assert.True(t, unchanged, "304 must be reported as unchanged")
	if p := sawINM.Load(); assert.NotNil(t, p) {
		assert.Equal(t, `"etag-v1"`, *p)
	}
}

func TestFetchPanelJSONErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	etagCache.Delete(srv.URL)
	var out ResponseData
	unchanged, err := FetchPanelJSON(srv.URL, &out)
	assert.Error(t, err)
	assert.False(t, unchanged)
}
