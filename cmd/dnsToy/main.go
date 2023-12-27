package main

import (
	"bufio"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	//"time"

	"github.com/chaoticcyber/dnsToy/internal/dbfunc"
	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
)

var (
	enableDNSLookup = true // Default is set to enable DNS lookup
	localDNS        string // Variable to hold the local DNS server address
	upstreamDNS     string // Variable to hold the upstream DNS server
	useGUI          bool   // Variable to determine GUI mode
)

func init() {
	flag.StringVar(&localDNS, "dns", "127.0.0.1", "Specify the local DNS server")
	flag.StringVar(&upstreamDNS, "udns", "8.8.8.8:53", "Specify the upstream DNS server")
	flag.BoolVar(&useGUI, "gui", false, "Run the application with GUI")
	flag.Parse()
}

func main() {
	// Open SQLite database for DNS resolutions
	database, err := sql.Open("sqlite3", "dns.db")
	if err != nil {
		log.Fatal(err)
	}
	defer database.Close()

	// Create resolutions table if it doesn't exist
	_, err = database.Exec(`CREATE TABLE IF NOT EXISTS resolutions (domain TEXT PRIMARY KEY, ip TEXT, query_count INTEGER DEFAULT 0)`)
	if err != nil {
		log.Fatal(err)
	}

	// Create a DNS server listening on UDP port 53
	dnsServer := &dns.Server{Addr: ":53", Net: "udp"}
	//client := dns.Client{Timeout: time.Second * 5} // Set a timeout for the query
	// Change DNS settings
	//if err := setDNS(localDNS); err != nil {
	//	fmt.Println(err)
	//	return
	//}

	go handleUserInput(database)

	// Handle DNS requests
	dnsServer.Handler = dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		// Prepare an empty DNS message to construct the response
		response := new(dns.Msg)
		response.SetReply(request)

		// Iterate through each question in the DNS request message
		for _, question := range request.Question {
			// Check if DNS lookup is enabled or if the domain is in the database
			if enableDNSLookup {
				// Check the type of DNS query
				fmt.Printf("DNS Lookup Enabled\n")
				if question.Qtype != dns.TypeA {
					// If it's not a query for A records, ignore and continue to the next query
					fmt.Printf("DNS Record is not an A record\n")
					continue
				}
				// Check if the queried domain exists in the resolutions database
				if resolvedIP, found := dbfunc.GetFromDatabase(database, strings.ToLower(question.Name)); found {
					// If found in resolutions, reply with the resolved IP
					fmt.Printf("The queried domain exists in the DB\n")
					ip := net.ParseIP(resolvedIP)
					if ip != nil {
						// Add the resolved IP to the DNS response as an A record
						answerRecord := dns.A{
							Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
							A:   ip,
						}
						response.Answer = append(response.Answer, &answerRecord)
					}
				} else {

					// If not found in the local database, forward the query to the upstream DNS server
					c := new(dns.Client)

					// Create a DNS message for PTR lookup
					mPtr := new(dns.Msg)
					mPtr.SetQuestion("8.8.8.8.in-addr.arpa.", dns.TypePTR) // PTR query for 8.8.8.8

					// Specify the DNS server to query (8.8.8.8 in this example)
					server := upstreamDNS

					// Send the PTR query
					respPtr, _, err := c.Exchange(mPtr, server)
					if err != nil {
						log.Fatalf("Error querying PTR record: %s", err)
					}
					targetName := question.Name
					// Use the obtained target name (if available) for the subsequent query (A record in this example)
					if targetName != "" {
						mA := new(dns.Msg)
						mA.SetQuestion(targetName, dns.TypeA) // A record query for the obtained name

						// Send the A record query
						respA, _, err := c.Exchange(mA, server)
						if err != nil {
							log.Fatalf("Error querying A record: %s", err)
						}

						// Extract the first IP address from the answer section
						var ipAddress string
						for _, ans := range respA.Answer {
							if a, ok := ans.(*dns.A); ok {
								fmt.Println("BeforeString")
								ipAddress = a.A.String()
								answerRecord := dns.A{
									Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
									A:   a.A,
								}
								response.Answer = append(response.Answer, &answerRecord)
								break // Stop after finding the first A record
							}
						}
						// Display the first IP address found
						if ipAddress != "" {
							fmt.Println(targetName)
							fmt.Println("The queried domain does NOT exist; adding", targetName, "to the DB with IP: ", ipAddress)
							err := dbfunc.AddToDatabase(database, question.Name, ipAddress)
							if err != nil {
								log.Printf("Error storing resolved IP in database: %s\n", err)
							}
						} else {
							fmt.Println("No A record found in the response")
						}
					} else {
						log.Println("PTR record did not return a valid target name")

						//fmt.Printf("The queried domain does NOT exist in the DB\n")

						// Extract and store the response from upstream to the local database
						for _, answer := range respPtr.Answer {
							if recordA, ok := answer.(*dns.A); ok {
								ip := recordA.A
								// Store the resolved IP in the local database
								fmt.Printf("The queried domain does NOT exist; adding it to the DB")
								err := dbfunc.AddToDatabase(database, recordA.Hdr.Name, ip.String())
								if err != nil {
									log.Printf("Error storing resolved IP in database: %s\n", err)
								}
								// Add the resolved IP to the DNS response as an A record
								answerRecord := dns.A{
									Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
									A:   ip,
								}
								response.Answer = append(response.Answer, &answerRecord)
							}
						}

						// 	resolvedIP, err := dbfunc.ResolveAndStore(database, strings.ToLower(question.Name))
						// 	if err != nil {
						// 		log.Printf("Error resolving and storing: %s\n", err)
						// 		continue
						// 	}
						// 	if resolvedIP != nil {
						// 		// Add the resolved IP to the DNS response as an A record
						// 		answerRecord := dns.A{
						// 			Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						// 			A:   resolvedIP,
						// 		}
						// 		response.Answer = append(response.Answer, &answerRecord)
						// 	}
					}
				}
			}
			if !enableDNSLookup {
				// If DNS lookup is disabled, check if domain exists in the database
				fmt.Printf("Lookups disabled, checking database.\n")
				if resolvedIP, found := dbfunc.GetFromDatabase(database, strings.ToLower(question.Name)); found {
					// If found in resolutions, reply with the resolved IP
					ip := net.ParseIP(resolvedIP)
					fmt.Printf("Domain Found!.\n")
					if ip != nil {
						// Add the resolved IP to the DNS response as an A record
						answerRecord := dns.A{
							Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
							A:   ip,
						}
						response.Answer = append(response.Answer, &answerRecord)
					}
					continue
				}
			}
		}
		// Send the DNS response back to the client
		err := writer.WriteMsg(response)
		if err != nil {
			log.Printf("Error writing DNS response: %s\n", err)
		}
	})

	// Start the DNS server
	go func() {
		fmt.Println("Starting DNS server...")
		if err := dnsServer.ListenAndServe(); err != nil {
			log.Fatalf("Error starting DNS server: %s\n", err)
		}
	}()

	// Wait for interruption to stop the server (Ctrl+C)
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	<-signalChannel

	fmt.Println("\nStopping DNS server...")
	dnsServer.Shutdown()
}

// Function to handle user input for database operations
func handleUserInput(db *sql.DB) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println("\nEnter 'dump' to display database contents, 'disable' to disable DNS lookups, 'enable' to enable DNS lookups, or 'exit' to quit:")
		text, _ := reader.ReadString('\n')
		text = strings.TrimSpace(text)

		switch text {
		case "dump":
			err := dbfunc.DumpDatabase(db)
			if err != nil {
				fmt.Println("Error dumping database:", err)
			}
		case "disable":
			enableDNSLookup = false
			fmt.Println("New DNS lookups disabled.")
		case "enable":
			enableDNSLookup = true
			fmt.Println("DNS lookups enabled.")
		case "exit":
			fmt.Println("Exiting...")
			os.Exit(0)
		default:
			fmt.Println("Invalid command. Try again.")
		}
	}
}

func setDNS(serverIP string) error {
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "dns", "name=Ethernet", "static", serverIP)
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("error setting DNS: %s", err)
	}
	return nil
}

func revertDNS() error {
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "dns", "name=Ethernet", "dhcp")
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("error reverting DNS: %s", err)
	}
	return nil
}
