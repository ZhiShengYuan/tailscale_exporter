package main

import (
    "encoding/json"
    "fmt"
    "net/http"
    "os/exec"
    "strings"
    "os"
)

type Status struct {
    Version         string              `json:"Version"`
    TUN             bool                `json:"TUN"`
    BackendState    string              `json:"BackendState"`
    AuthURL         string              `json:"AuthURL"`
    TailscaleIPs    []string            `json:"TailscaleIPs"`
    Self            Node                `json:"Self"`
    Health          interface{}         `json:"Health"`
    MagicDNSSuffix  string              `json:"MagicDNSSuffix"`
    CurrentTailnet  CurrentTailnet      `json:"CurrentTailnet"`
    CertDomains     interface{}         `json:"CertDomains"`
    Peer            map[string]PeerNode `json:"Peer"`
    User            map[int]UserInfo    `json:"User"`
    ClientVersion   ClientVersion       `json:"ClientVersion"`
}

type Node struct {
    ID              string      `json:"ID"`
    PublicKey       string      `json:"PublicKey"`
    HostName        string      `json:"HostName"`
    DNSName         string      `json:"DNSName"`
    OS              string      `json:"OS"`
    UserID          int         `json:"UserID"`
    TailscaleIPs    []string    `json:"TailscaleIPs"`
    AllowedIPs      []string    `json:"AllowedIPs"`
    Addrs           []string    `json:"Addrs"`
    CurAddr         string      `json:"CurAddr"`
    Relay           string      `json:"Relay"`
    RxBytes         int         `json:"RxBytes"`
    TxBytes         int         `json:"TxBytes"`
    Created         string      `json:"Created"`
    LastWrite       string      `json:"LastWrite"`
    LastSeen        string      `json:"LastSeen"`
    LastHandshake   string      `json:"LastHandshake"`
    Online          bool        `json:"Online"`
    ExitNode        bool        `json:"ExitNode"`
    ExitNodeOption  bool        `json:"ExitNodeOption"`
    Active          bool        `json:"Active"`
    PeerAPIURL      []string    `json:"PeerAPIURL"`
    Capabilities    []string    `json:"Capabilities"`
    CapMap          interface{} `json:"CapMap"`
    InNetworkMap    bool        `json:"InNetworkMap"`
    InMagicSock     bool        `json:"InMagicSock"`
    InEngine        bool        `json:"InEngine"`
}

type CurrentTailnet struct {
    Name            string  `json:"Name"`
    MagicDNSSuffix  string  `json:"MagicDNSSuffix"`
    MagicDNSEnabled bool    `json:"MagicDNSEnabled"`
}

type PeerNode struct {
    ID              string      `json:"ID"`
    PublicKey       string      `json:"PublicKey"`
    HostName        string      `json:"HostName"`
    DNSName         string      `json:"DNSName"`
    OS              string      `json:"OS"`
    UserID          int         `json:"UserID"`
    TailscaleIPs    []string    `json:"TailscaleIPs"`
    AllowedIPs      []string    `json:"AllowedIPs"`
    PrimaryRoutes   []string    `json:"PrimaryRoutes"`
    Addrs           interface{} `json:"Addrs"`
    CurAddr         string      `json:"CurAddr"`
    Relay           string      `json:"Relay"`
    RxBytes         int         `json:"RxBytes"`
    TxBytes         int         `json:"TxBytes"`
    Created         string      `json:"Created"`
    LastWrite       string      `json:"LastWrite"`
    LastSeen        string      `json:"LastSeen"`
    LastHandshake   string      `json:"LastHandshake"`
    Online          bool        `json:"Online"`
    ExitNode        bool        `json:"ExitNode"`
    ExitNodeOption  bool        `json:"ExitNodeOption"`
    Active          bool        `json:"Active"`
    PeerAPIURL      []string    `json:"PeerAPIURL"`
    InNetworkMap    bool        `json:"InNetworkMap"`
    InMagicSock     bool        `json:"InMagicSock"`
    InEngine        bool        `json:"InEngine"`
}

type UserInfo struct {
    ID              int     `json:"ID"`
    LoginName       string  `json:"LoginName"`
    DisplayName     string  `json:"DisplayName"`
    ProfilePicURL   string  `json:"ProfilePicURL"`
    Roles           []string`json:"Roles"`
}

type ClientVersion struct {
    RunningLatest   bool    `json:"RunningLatest"`
}
func basicAuth(handler http.HandlerFunc, username, password string) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        user, pass, ok := r.BasicAuth()
        if !ok || user != username || pass != password {
            w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
            w.WriteHeader(http.StatusUnauthorized)
            fmt.Fprintln(w, "Unauthorized access")
            return
        }
        handler(w, r)
    }
}
func main() {
    if len(os.Args) < 4 {
        fmt.Println("Usage: go run main.go <port> <username> <password>")
        return
    }

    port := os.Args[1]
    username := os.Args[2]
    password := os.Args[3]

    http.HandleFunc("/metrics", basicAuth(func(w http.ResponseWriter, r *http.Request) {
        status := getStatus()
        prometheusData := formatPrometheusData(status)
        fmt.Fprintln(w, prometheusData)
    }, username, password))

    http.ListenAndServe(":"+port, nil)
}


func getStatus() Status {
    cmd := exec.Command("tailscale", "status", "--json")
    output, err := cmd.Output()
    if err != nil {
        fmt.Println("Error executing command:", err)
    }

    var status Status
    err = json.Unmarshal(output, &status)
    if err != nil {
        fmt.Println("Error parsing JSON:", err)
    }

    return status
}
func ConvertToString(value interface{}) string {
    return fmt.Sprintf("%v", value)
}
func formatPrometheusData(status Status) string {
    var sb strings.Builder
    fmt.Fprintf(&sb, "# HELP tailscale_info Information about Tailscale status\n")
    fmt.Fprintf(&sb, "# TYPE tailscale_info gauge\n")
    fmt.Fprintf(&sb, "tailscale_version{version=\"%s\"} 1\n", status.Version)
    tunValue := 0
    if status.TUN {
        tunValue = 1
    }
    fmt.Fprintf(&sb, "tailscale_tun %d\n", tunValue)
    fmt.Fprintf(&sb, "tailscale_backend_state{state=\"%s\"} 1\n", status.BackendState)
    for _,peer := range status.Peer {
        fmt.Fprintf(&sb, "tailscale_peer_cur_addr{id=\"%s\"} %s\n", peer.HostName,  ConvertToString(peer.CurAddr))
        fmt.Fprintf(&sb, "tailscale_peer_rx_bytes{id=\"%s\"} %s\n", peer.HostName,  ConvertToString(peer.RxBytes))
        fmt.Fprintf(&sb, "tailscale_peer_tx_bytes{id=\"%s\"} %s\n", peer.HostName,  ConvertToString(peer.TxBytes))
        fmt.Fprintf(&sb, "tailscale_peer_cur_addr{id=\"%s\"} %s\n", peer.HostName,  ConvertToString(peer.CurAddr))
        fmt.Fprintf(&sb, "tailscale_peer_relay{id=\"%s\"} %s\n", peer.HostName,  ConvertToString(peer.Relay))
        fmt.Fprintf(&sb, "tailscale_peer_direct{id=\"%s\"} %s\n", peer.HostName, ConvertToString(peer.CurAddr != ""))
        fmt.Fprintf(&sb, "tailscale_peer_online{id=\"%s\"} %s\n", peer.HostName,  ConvertToString(peer.Online))
        fmt.Fprintf(&sb, "tailscale_peer_ExitNode{id=\"%s\"} %s\n", peer.HostName,  ConvertToString(peer.ExitNode))
        fmt.Fprintf(&sb, "tailscale_peer_Active{id=\"%s\"} %s\n", peer.HostName,  ConvertToString(peer.Active))
        fmt.Fprintf(&sb, "tailscale_peer_InNetworkMap{id=\"%s\"} %s\n", peer.HostName,  ConvertToString(peer.InNetworkMap))
        fmt.Fprintf(&sb, "tailscale_peer_InMagicSock{id=\"%s\"} %s\n", peer.HostName,  ConvertToString(peer.InMagicSock))
        fmt.Fprintf(&sb, "tailscale_peer_InEngine{id=\"%s\"} %s\n", peer.HostName,  ConvertToString(peer.InEngine))

    }
    return sb.String()
}
