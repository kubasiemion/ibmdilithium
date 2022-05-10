package ibmdilithium

import (
	"fmt"

	pb "github.com/IBM-Cloud/hpcs-grep11-go/grpc"
	"google.golang.org/grpc"
)

var (
	Address = "10.7.17.241:9876"
)

var conn *grpc.ClientConn

func CryptoClient() pb.CryptoClient {
	var err error
	conn, err = grpc.Dial(Address, testCallOpts...)
	grpc.WaitForReady(true)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	return pb.NewCryptoClient(conn)
}

func Close() {
	if conn != nil {
		conn.Close()
	}
}

var testCallOpts = []grpc.DialOption{
	grpc.WithInsecure(),
	grpc.WithBlock(),
}
