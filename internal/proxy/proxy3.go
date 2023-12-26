package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
)

var enableDNSLookup = true // Default is set to enable DNS lookup

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
				if question.Qtype != dns.TypeA {
					// If it's not a query for A records, ignore and continue to the next query
					continue
				}
				// Perform the DNS resolution to get the IP address
				ips, err := net.LookupIP(question.Name)
				if err != nil {
					log.Printf("Error resolving %s: %s\n", question.Name, err)
					continue
				}

				// Take the first resolved IP address
				var resolvedIP net.IP
				if len(ips) > 0 {
					resolvedIP = ips[0]
				}

				// Perform database update with the client's IP address
				exists, err := existsInDatabaseIncrementCount(database, strings.ToLower(question.Name), resolvedIP)
				if err != nil {
					log.Printf("Error checking database or incrementing count for %s: %s\n", question.Name, err)
					continue
				}
				if !exists {
					// If domain doesn't exist and was inserted, respond with empty response
					// Log received A record DNS queries
					fmt.Printf("New domain added to the database: %s\n", question.Name)
					continue
				}

				// Check if the queried domain exists in the resolutions database
				if resolvedIP, found := getFromDatabase(database, strings.ToLower(question.Name)); found {
					// If found in resolutions, reply with the resolved IP
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
					// If not found, perform DNS resolution and store in the database
					resolvedIP, err := resolveAndStore(database, strings.ToLower(question.Name))
					if err != nil {
						log.Printf("Error resolving and storing: %s\n", err)
						continue
					}
					if resolvedIP != nil {
						// Add the resolved IP to the DNS response as an A record
						answerRecord := dns.A{
							Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
							A:   resolvedIP,
						}
						response.Answer = append(response.Answer, &answerRecord)
					}
				}
			}
			if !enableDNSLookup {
				// If DNS lookup is disabled, check if domain exists in the database
				if resolvedIP, found := getFromDatabase(database, strings.ToLower(question.Name)); found {
					// If found in resolutions, reply with the resolved IP
					ip := net.ParseIP(resolvedIP)
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

// Function to query the database for domain resolution
func getFromDatabase(db *sql.DB, domain string) (string, bool) {
	var resolvedIP string
	err := db.QueryRow("SELECT ip FROM resolutions WHERE domain=?", domain).Scan(&resolvedIP)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", false // Domain not found in database
		}
		log.Println(err)
		return "", false
	}
	return resolvedIP, true // Domain found in database
}

// Function to perform DNS resolution and store in the database
func resolveAndStore(db *sql.DB, domain string) (net.IP, error) {
	resolvedIPs, err := net.LookupIP(domain)
	if err != nil {
		return nil, err
	}

	if len(resolvedIPs) == 0 {
		return nil, fmt.Errorf("no IP addresses found for %s", domain)
	}

	// Choose the first resolved IP address
	resolvedIP := resolvedIPs[0]

	// Store the resolved IP in the database
	err = addToDatabase(db, domain, resolvedIP.String())
	if err != nil {
		return nil, err
	}

	return resolvedIP, nil
}

// Function to add a domain and its resolution to the database
func addToDatabase(db *sql.DB, domain, ip string) error {
	_, err := db.Exec("INSERT INTO resolutions(domain, ip) VALUES(?, ?)", domain, ip)
	return err
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
			err := dumpDatabase(db)
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

// Function to dump the contents of the database
func dumpDatabase(db *sql.DB) error {
	rows, err := db.Query("SELECT domain, ip, query_count FROM resolutions")
	if err != nil {
		return err
	}
	defer rows.Close()

	// Print the table header
	fmt.Println("\nDatabase contents:")
	fmt.Printf("%-40s%-30s%-30s\n", "DOMAIN", "IP", "QUERY COUNT")
	fmt.Println("---------------------------------------------------------------------------------")

	// Iterate through database rows and print each row in the table
	for rows.Next() {
		var domain, ip string
		var queryCount int
		if err := rows.Scan(&domain, &ip, &queryCount); err != nil {
			return err
		}
		fmt.Printf("%-40s%-30s%-30d\n", domain, ip, queryCount)
	}
	return nil
}

// Function to check if a domain exists in the database and increment its query count (with IP)
func existsInDatabaseIncrementCount(db *sql.DB, domain string, ip net.IP) (bool, error) {
	var count int
	err := db.QueryRow("SELECT query_count FROM resolutions WHERE domain=?", domain).Scan(&count)
	if err != nil {
		if err == sql.ErrNoRows {
			// If domain doesn't exist, insert it with IP and a query count of 1
			_, err := db.Exec("INSERT INTO resolutions(domain, ip, query_count) VALUES(?, ?, 0)", domain, ip.String())
			if err != nil {
				return false, err
			}
			return false, nil
		}
		return false, err
	}

	// Increment the query count for the domain
	_, err = db.Exec("UPDATE resolutions SET query_count=query_count+1 WHERE domain=?", domain)
	if err != nil {
		return false, err
	}
	return true, nil
}
