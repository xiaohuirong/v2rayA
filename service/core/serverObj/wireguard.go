package serverObj

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/v2rayA/v2rayA/core/coreObj"
)

func init() {
	FromLinkRegister("wireguard", NewWireguard)
	FromLinkRegister("wg", NewWireguard)
	EmptyRegister("wireguard", func() (ServerObj, error) {
		return new(Wireguard), nil
	})
}

type Wireguard struct {
	Name            string   `json:"name"`
	Server          string   `json:"server"`
	Port            string   `json:"port"`
	PeerPubKey      string   `json:"peerPubKey"`
	SecretKey       string   `json:"secretKey"`
	LocalAddress    []string `json:"localAddress"`
	PreSharedKey    string   `json:"preSharedKey,omitempty"`
	KeepAlive       int      `json:"keepAlive"`
	MTU             int      `json:"mtu"`
	Reserved        []uint8  `json:"reserved,omitempty"`
	Protocol        string   `json:"protocol"`
}

func NewWireguard(link string) (ServerObj, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	q := u.Query()

	name := q.Get("name")
	if name == "" {
		name = u.Fragment
	}
	
	peerPubKey := u.User.Username()
	if peerPubKey == "" {
		peerPubKey = q.Get("publicKey")
	}
	
	secretKey := q.Get("secretKey")
	if secretKey == "" {
		secretKey = q.Get("privateKey")
	}

	wg := &Wireguard{
		Name:         name,
		Server:       u.Hostname(),
		Port:         u.Port(),
		PeerPubKey:   peerPubKey,
		SecretKey:    secretKey,
		PreSharedKey: q.Get("psk"),
		Protocol:     "wireguard",
	}

	if addresses := q.Get("address"); addresses != "" {
		wg.LocalAddress = strings.Split(addresses, ",")
	}
	if keepAliveStr := q.Get("keepAlive"); keepAliveStr != "" {
		if keepAlive, err := strconv.Atoi(keepAliveStr); err == nil {
			wg.KeepAlive = keepAlive
		}
	}
	if mtu := q.Get("mtu"); mtu != "" {
		wg.MTU, _ = strconv.Atoi(mtu)
	}
	if reserved := q.Get("reserved"); reserved != "" {
		var res []uint8
		for _, v := range strings.Split(reserved, ",") {
			r, _ := strconv.Atoi(strings.TrimSpace(v))
			res = append(res, uint8(r))
		}
		wg.Reserved = res
	}

	return wg, nil
}

func ParseWireguardConf(confString string) (*Wireguard, error) {
	lines := strings.Split(confString, "\n")
	wg := &Wireguard{
		Name:     "Wireguard",
		Protocol: "wireguard",
	}

	var currentSection string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])

		if strings.EqualFold(currentSection, "Interface") {
			switch key {
			case "privatekey":
				wg.SecretKey = val
			case "address":
				for _, addr := range strings.Split(val, ",") {
					addr = strings.TrimSpace(addr)
					if addr != "" {
						wg.LocalAddress = append(wg.LocalAddress, addr)
					}
				}
			case "mtu":
				if mtu, err := strconv.Atoi(val); err == nil && mtu >= 0 {
					wg.MTU = mtu
				}
			}
		} else if strings.EqualFold(currentSection, "Peer") {
			switch key {
			case "publickey":
				wg.PeerPubKey = val
			case "presharedkey":
				wg.PreSharedKey = val
			case "endpoint":
				host, port, err := net.SplitHostPort(val)
				if err == nil {
					wg.Server = host
					wg.Port = port
				} else {
					wg.Server = val
				}
			case "persistentkeepalive":
				if keepAlive, err := strconv.Atoi(val); err == nil && keepAlive >= 0 {
					wg.KeepAlive = keepAlive
				}
			}
		}
	}

	if wg.PeerPubKey == "" || wg.SecretKey == "" || wg.Server == "" {
		return nil, fmt.Errorf("invalid wireguard configuration: missing required fields")
	}

	return wg, nil
}

type WgPeer struct {
	Endpoint     string   `json:"endpoint"`
	PublicKey    string   `json:"publicKey"`
	PreSharedKey string   `json:"preSharedKey,omitempty"`
	KeepAlive    int      `json:"keepAlive"`
	AllowedIPs   []string `json:"allowedIPs"`
}

func (w *Wireguard) Configuration(info PriorInfo) (c Configuration, err error) {
	core := coreObj.OutboundObject{
		Tag:      info.Tag,
		Protocol: "wireguard",
	}

	peers := []WgPeer{
		{
			Endpoint:     net.JoinHostPort(w.Server, w.Port),
			PublicKey:    w.PeerPubKey,
			PreSharedKey: w.PreSharedKey,
			KeepAlive:    w.KeepAlive,
			AllowedIPs:   []string{"0.0.0.0/0", "::/0"},
		},
	}

	core.Settings = coreObj.Settings{
		SecretKey:      w.SecretKey,
		Address:        w.LocalAddress,
		Peers:          peers,
		Reserved:       w.Reserved,
		DomainStrategy: "ForceIP",
		Workers:        2,
	}

	if w.MTU > 0 {
		core.Settings.MTU = w.MTU
	}

	return Configuration{
		CoreOutbound: core,
		PluginChain:  "",
		UDPSupport:   true,
	}, nil
}

func (w *Wireguard) ExportToURL() string {
	q := url.Values{}
	setValue(&q, "name", w.Name)
	setValue(&q, "secretKey", w.SecretKey)
	setValue(&q, "address", strings.Join(w.LocalAddress, ","))
	setValue(&q, "psk", w.PreSharedKey)
	if w.KeepAlive >= 0 {
		setValue(&q, "keepAlive", strconv.Itoa(w.KeepAlive))
	}
	if w.MTU > 0 {
		setValue(&q, "mtu", strconv.Itoa(w.MTU))
	}
	if len(w.Reserved) > 0 {
		var resStr []string
		for _, r := range w.Reserved {
			resStr = append(resStr, strconv.Itoa(int(r)))
		}
		setValue(&q, "reserved", strings.Join(resStr, ","))
	}

	u := url.URL{
		Scheme:   "wireguard",
		User:     url.User(w.PeerPubKey),
		Host:     net.JoinHostPort(w.Server, w.Port),
		RawQuery: q.Encode(),
	}
	return u.String()
}

func (w *Wireguard) NeedPluginPort() bool {
	return false
}

func (w *Wireguard) ProtoToShow() string {
	return "wireguard"
}

func (w *Wireguard) GetProtocol() string {
	return "wireguard"
}

func (w *Wireguard) GetHostname() string {
	return w.Server
}

func (w *Wireguard) GetPort() int {
	p, _ := strconv.Atoi(w.Port)
	return p
}

func (w *Wireguard) GetName() string {
	return w.Name
}

func (w *Wireguard) SetName(name string) {
	w.Name = name
}
