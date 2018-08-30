package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"github.com/mcuadros/go-version"
	"log"
	"net"
)

// These were taken from MySQL latest's source code. Not sure if they are
// totally up to date. Just using them for name translations.
var SERVER_STATUS = map[uint16]string{
	1:    "SERVER_STATUS_IN_TRANS",
	2:    "SERVER_STATUS_AUTOCOMMIT",
	8:    "SERVER_MORE_RESULTS_EXISTS",
	16:   "SERVER_QUERY_NO_GOOD_INDEX_USED",
	32:   "SERVER_QUERY_NO_INDEX_USED",
	64:   "SERVER_STATUS_CURSOR_EXISTS",
	128:  "SERVER_STATUS_LAST_ROW_SENT",
	256:  "SERVER_STATUS_DB_DROPPED",
	512:  "SERVER_STATUS_NO_BACKSLASH_ESCAPES",
	1024: "SERVER_STATUS_METADATA_CHANGED",
	2048: "SERVER_QUERY_WAS_SLOW",
	4096: "SERVER_PS_OUT_PARAMS",
	8192: "SERVER_STATUS_IN_TRANS_READONLY",
}

// Copied these from some online docs.
var CAPABILITIES = map[uint16]string{
	1:     "CLIENT_LONG_PASSWORD",
	2:     "CLIENT_FOUND_ROWS",
	4:     "CLIENT_LONG_FLAG",
	8:     "CLIENT_CONNECT_WITH_DB",
	16:    "CLIENT_NO_SCHEMA",
	32:    "CLIENT_COMPRESS",
	64:    "CLIENT_ODBC",
	128:   "CLIENT_LOCAL_FILES",
	256:   "CLIENT_IGNORE_SPACE",
	512:   "CLIENT_PROTOCOL_41",
	1024:  "CLIENT_INTERACTIVE",
	2048:  "CLIENT_SSL",
	4096:  "CLIENT_IGNORE_SIGPIPE",
	8192:  "CLIENT_TRANSACTIONS",
	16384: "CLIENT_RESERVED",
	32768: "CLIENT_SECURE_CONNECTION",
}

// Offsets and lengths to be used when referencing into the packet. Just pulling
// them out here so they aren't magical numbers or variable getting redefined
// during every function call.
const VERSION_OFFSET = 5

const CAPABILITY_OFFSET = 14
const CAPABILITY_LENGTH = 2

const THREAD_ID_OFFSET = 1
const THREAD_ID_LENGTH = 4

const CHARACTER_SET_OFFSET = 16

const SERVER_STATUS_OFFSET = 17
const SERVER_STATUS_LENGTH = 2

const RANDOM_SEED_OFFSET = 5
const RANDOM_SEED_LENGTH = 9

const RANDOM_REST_OFFSET = 32
const RANDOM_REST_LENGTH = 13

// The base struct. Its not much here, just the packet which is the bytes
// payload of the MySQL response and the version_length, which should be
// calculated before any other method associated with the struct is used. Please
// don't create a new one of these yourself but instead use the
// NewMySQLHandshake constructor.
type MySQLHandshake struct {
	packet         []byte
	version_length int
}

// Most offsets from the handshake are based on the variable lengthed, 0
// terminated version string. This is just an accessor method that is given the
// offset past the version string, and returns the offset into the entire packet.
func (r *MySQLHandshake) get_post_version_offset(offset int) int {
	return VERSION_OFFSET + r.version_length + offset
}

// Get the scramble bytes. This one is slightly more involved as it appears
// older versions of MySQL reported it differently.
func (r *MySQLHandshake) scramble() []byte {
	v := r.version()
	start := r.get_post_version_offset(RANDOM_SEED_OFFSET)
	end := start + RANDOM_SEED_LENGTH

	if version.Compare(v, "4.1", ">=") {
		rest_start := r.get_post_version_offset(RANDOM_REST_OFFSET)
		rest_end := rest_start + RANDOM_REST_LENGTH
		combined := append(r.packet[start:end],
			r.packet[rest_start:rest_end]...)

		idx := 0
		for _, element := range combined {
			if element == 0 {
				break
			}
			idx += 1
		}

		return combined[:idx]
	} else {
		start := r.get_post_version_offset(RANDOM_SEED_OFFSET)
		end := start + RANDOM_SEED_LENGTH
		return r.packet[start:end]
	}

}

// Get the greeting of the MySQL handshake, I was unable to find a meaning for
// what the greeting actually meant.
func (r *MySQLHandshake) greeting() []byte {
	return r.packet[:4]
}

// Get the server capabilities from the handshake.
func (r *MySQLHandshake) capabilities() uint16 {
	start := r.get_post_version_offset(CAPABILITY_OFFSET)
	end := start + CAPABILITY_LENGTH
	return binary.LittleEndian.Uint16(r.packet[start:end])
}

// Get the server status, which I think i MySQL means the default values that
// the client will connect with if not explicitly overriden.
func (r *MySQLHandshake) server_status() uint16 {
	start := r.get_post_version_offset(SERVER_STATUS_OFFSET)
	end := start + SERVER_STATUS_LENGTH
	return binary.LittleEndian.Uint16(r.packet[start:end])
}

// Get the character set used by default with the MySQL server. I couldn't find
// a proper enumeration for what these should translate to.
func (r *MySQLHandshake) character_set() int {
	start := r.get_post_version_offset(CHARACTER_SET_OFFSET)
	return int(r.packet[start])
}

// Get the protcol of the MySQL communication. Looks like this is just always 10
// from reading some docs.
func (r *MySQLHandshake) protocol() int {
	// No uint8 converter in binary? Hmm...
	return int(r.packet[4])
}

// Extract the version string from handshake.
func (r *MySQLHandshake) version() string {
	return string(r.packet[VERSION_OFFSET : VERSION_OFFSET+r.version_length])
}

// Get the MySQL thread ID from the handshake.
func (r *MySQLHandshake) mysql_thread_id() uint32 {
	start := r.get_post_version_offset(THREAD_ID_OFFSET)
	end := start + THREAD_ID_LENGTH
	return binary.LittleEndian.Uint32(r.packet[start:end])
}

// Just a quick and dirty printer for printing out the struct.
func (r *MySQLHandshake) String() string {
	return fmt.Sprintf("MySQLHandshake("+
		"protocol=%d, "+
		"version_length=%d, "+
		"version=%s, "+
		"mysql_thread_id=%d, "+
		"server_status=%d, "+
		"scramble=%v, "+
		"character_set=%d, "+
		"capabilities=%v"+
		")",
		r.protocol(),
		r.version_length,
		r.version(),
		r.mysql_thread_id(),
		r.server_status(),
		r.scramble(),
		r.character_set(),
		r.capabilities())
}

// What the scanner is intended to use for printing out human readable results
// about the scan. Prints directly to stdout. Ideally I'd want to log this
// somewhere else or control where it goes a little better, but for this POC it
// should work fine.
func (r *MySQLHandshake) prettyPrint() {
	fmt.Println("MySQL Handshake Dump")
	fmt.Println("====================")
	fmt.Println("    MySQL Version:\t", r.version())
	fmt.Println("    MySQL Protocol:\t", r.protocol())
	fmt.Println("    MySQL Char Set:\t", r.character_set())
	fmt.Println("    MySQL Thread ID:\t", r.mysql_thread_id())
	fmt.Println("    MySQL Server Status:")

	server_status := r.server_status()
	for k, v := range SERVER_STATUS {
		if k&server_status != 0 {
			fmt.Println("     - ", v)
		}
	}

	fmt.Println("    MySQL Capabilities:")

	capabilities := r.capabilities()
	for k, v := range CAPABILITIES {
		if k&capabilities != 0 {
			fmt.Println("     - ", v)
		}
	}

	fmt.Println("    MySQL Scramble:\t", r.scramble())
}

// Constructor for the NewMySQLHandshake struct. I need to initialize the
// version length variable in the struct because all other fields after it
// depend on knowing that length. After doing that we can just return the struct.
func NewMySQLHandshake(packet []byte) *MySQLHandshake {
	h := new(MySQLHandshake)
	h.packet = packet

	version_idx := 5
	version_length := 0

	// Not totally sure about Go's scoping rules with when variables exist
	// outside of a block, so I'm just doing something dumb here where I'm
	// incrementing version length.
	for _, element := range h.packet[version_idx:] {
		if element == 0 {
			break
		}
		version_length += 1
	}

	// Should return an error here if version_length == 0, not super sure
	// how Golang's errors work so I'll just elide that here.

	h.version_length = version_length
	return h
}

func main() {
	p := make([]byte, 128)
	// For now I'm going to assume
	conn, err := net.Dial("tcp", "127.0.0.1:3306")

	if err != nil {
		log.Println("Error connecting on UDP socket: ", err)
		return
	}

	_, err = bufio.NewReader(conn).Read(p)

	if err != nil {
		log.Println("Error sending and reading UDP response: ", err)
		return
	}

	handshake := NewMySQLHandshake(p)
	handshake.prettyPrint()
}
