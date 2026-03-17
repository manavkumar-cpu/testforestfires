from xmlrpc.server import SimpleXMLRPCServer

def multiply_matrices(A, B):
    result = [[0 for _ in range(len(B[0]))] for _ in range(len(A))]
    for i in range(len(A)):
        for j in range(len(B[0])):
            for k in range(len(B)):
                result[i][j] += A[i][k] * B[k][j]
    return result

server = SimpleXMLRPCServer(("localhost", 6000))
print("RPC Server running...")

server.register_function(multiply_matrices, "multiply")
server.serve_forever()
