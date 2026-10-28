package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// panelHTTP 限制面板 API 请求耗时，防止面板挂起拖死同步循环
var panelHTTP = &http.Client{Timeout: 10 * time.Second}

// etagCache 记住每个面板 URL 上次的 ETag，配合 If-None-Match 使用
var etagCache sync.Map // url → etag string

// FetchPanelJSON 请求面板 API 并解码 JSON。
// 返回 unchanged=true 表示面板返回 304，调用方必须跳过后续处理
// （不能拿零值/空列表去覆盖本地状态）。
func FetchPanelJSON(target string, out any) (unchanged bool, err error) {
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return false, err
	}
	if etag, ok := etagCache.Load(target); ok {
		req.Header.Set("If-None-Match", etag.(string))
	}
	resp, err := panelHTTP.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		return true, nil
	case http.StatusOK:
		if etag := resp.Header.Get("ETag"); etag != "" {
			etagCache.Store(target, etag)
		}
		return false, json.NewDecoder(resp.Body).Decode(out)
	default:
		return false, fmt.Errorf("panel request failed with status code: %s", resp.Status)
	}
}
