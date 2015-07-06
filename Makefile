CXXFLAGS += -std=c++11 -Wall -pedantic -lpam -lgrpc++ -lgrpc -lgpr -lboost_log `pkg-config --libs --cflags protobuf`

murmur-auth-pam: main.cpp MurmurRPC/MurmurRPC.o MurmurRPC/MurmurRPC.grpc.o
	$(CXX) -o $@ main.cpp MurmurRPC/MurmurRPC.o MurmurRPC/MurmurRPC.grpc.o $(CXXFLAGS)

MurmurRPC/MurmurRPC.o: MurmurRPC/MurmurRPC.pb.cc MurmurRPC/MurmurRPC.pb.h
	$(CXX) -c -o $@ $< $(CXXFLAGS)

MurmurRPC/MurmurRPC.pb.cc MurmurRPC/MurmurRPC.pb.h: MurmurRPC.proto
	protoc -I. --cpp_out=MurmurRPC MurmurRPC.proto

MurmurRPC/MurmurRPC.grpc.o: MurmurRPC/MurmurRPC.grpc.pb.cc MurmurRPC/MurmurRPC.grpc.pb.h
	$(CXX) -c -o $@ $< $(CXXFLAGS)

MurmurRPC/MurmurRPC.grpc.pb.cc MurmurRPC/MurmurRPC.grpc.pb.h: MurmurRPC.proto
	protoc -I. --plugin=protoc-gen-grpc=/usr/bin/grpc_cpp_plugin --grpc_out=MurmurRPC MurmurRPC.proto
