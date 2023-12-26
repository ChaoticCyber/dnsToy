package dbfunc

import (
	"database/sql"
	"fmt"
	"log"
	"net"

	_ "github.com/mattn/go-sqlite3"
)

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
