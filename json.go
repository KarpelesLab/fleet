package fleet

type JsonCloudFleet struct {
	Id         string `json:"Cloud_Fleet__"`
	DivisionId string `json:"Cloud_Fleet_Division__"`
	Name       string
	Project    string
	Hostname   string
}

type JsonFleetHostInfo struct {
	Id         string `json:"Cloud_Fleet_Division_Host__"`
	DivisionId string `json:"Cloud_Fleet_Division__"`
	FleetId    string `json:"Cloud_Fleet__"`
	Name       string
	Index      string // actually int
	AZ         string `json:"Availability_Zone"`
	Ip         string
	InternalIp string `json:"Internal_Ip"`
	Instance   string
	Type       string
	Fleet      *JsonCloudFleet `json:"Cloud_Fleet"`
}
