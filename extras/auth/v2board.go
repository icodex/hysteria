package auth

import (
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
)

var _ server.Authenticator = &V2boardApiProvider{}

type V2boardApiProvider struct {
	URL string
}

// 用户列表
var (
	usersMap map[string]User
	lock     sync.Mutex

	// WSActive 为 true 时面板走 WS 推送，REST 轮询让位
	WSActive atomic.Bool
)

type User struct {
	ID          int     `json:"id"`
	UUID        string  `json:"uuid"`
	SpeedLimit  *uint32 `json:"speed_limit"`
	DeviceLimit int     `json:"device_limit"`
}
type ResponseData struct {
	Users []User `json:"users"`
}

func getUserList(url string) (users []User, unchanged bool, err error) {
	var responseData ResponseData
	unchanged, err = FetchPanelJSON(url, &responseData)
	if err != nil {
		return nil, false, err
	}
	if unchanged {
		return nil, true, nil
	}
	return responseData.Users, false, nil
}

func UpdateUsers(url string, interval time.Duration, trafficlogger server.TrafficLogger) {
	log.Println("用户列表自动更新服务已激活，更新周期为", interval)

	// 面板瞬时不可达只跳过本轮，永不退出同步循环
	fetch := func() {
		userList, unchanged, err := getUserList(url)
		if err != nil {
			log.Println("v2board user list fetch failed:", err)
			return
		}
		if unchanged {
			return
		}
		ApplyUsers(userList, trafficlogger)
	}
	fetch()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		if WSActive.Load() {
			continue
		}
		fetch()
	}
}

// ApplyUsers 全量替换用户列表，被移除的用户触发踢出
func ApplyUsers(userList []User, trafficlogger server.TrafficLogger) {
	lock.Lock()

	newUsersMap := make(map[string]User, len(userList))
	newLimiters := make(map[int]*uint32, len(userList))
	for _, user := range userList {
		newUsersMap[user.UUID] = user
		newLimiters[user.ID] = user.SpeedLimit
	}
	if trafficlogger != nil {
		for uuid := range usersMap {
			if _, exists := newUsersMap[uuid]; !exists {
				trafficlogger.NewKick(strconv.Itoa(usersMap[uuid].ID))
			}
		}
	}
	usersMap = newUsersMap
	lock.Unlock()

	rebuildSpeedLimiters(newLimiters)
}

// ApplyUserDelta 增量更新用户（面板 sync.user.delta：add 带 uuid，remove 只带 id）
func ApplyUserDelta(add bool, users []User, trafficlogger server.TrafficLogger) {
	lock.Lock()

	if usersMap == nil {
		usersMap = make(map[string]User)
	}
	for _, user := range users {
		if add {
			if user.UUID != "" {
				usersMap[user.UUID] = user
			}
			continue
		}
		for uuid, u := range usersMap {
			if u.ID == user.ID {
				delete(usersMap, uuid)
				if trafficlogger != nil {
					trafficlogger.NewKick(strconv.Itoa(user.ID))
				}
				break
			}
		}
	}
	lock.Unlock()

	if add {
		for _, user := range users {
			updateSpeedLimiter(user.ID, user.SpeedLimit)
		}
	} else {
		for _, user := range users {
			removeSpeedLimiter(user.ID)
		}
	}
}

// 验证代码
func (v *V2boardApiProvider) Authenticate(addr net.Addr, auth string, tx uint64) (ok bool, id string) {
	// 获取判断连接用户是否在用户列表内
	lock.Lock()
	defer lock.Unlock()

	if user, exists := usersMap[auth]; exists {
		if deviceLimitReject(user.ID, user.DeviceLimit, addr) {
			return false, ""
		}
		return true, strconv.Itoa(user.ID)
	}
	return false, ""
}
