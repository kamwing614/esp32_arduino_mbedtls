This contains a half completed custom communication protocol between two nodes:

Node A(Client 1):
3.6 is completed
  //1.receive the cert & RB (plaintext form)
  //2.verify the peer's cert, is it signed by trusted CA?
  //2.1 load the cert_buf into cert context
  //2.2 verify the cert. Is it signed by trusted CA?
  //3.send the cert &( AF1||AF2||RA||RB )encrypted by peer's cert && 
  //3.2generate af1,af2,ra
  //3.3concatengate af1,af2,ra,rb in the form of (8bytes||8bytes||8bytes||8bytes)
  //3.4 encrypt the msg
  //3.5 sign the message
  //3.6 send the cert, cipher, signature
  //4.receive  ( BF1 || BF2 || RA ) encrypted using my cert || (BF1||BF2||RA) sign with peer cert
  //4.1 decrypt the message to get (BF1||BF2||RA)
  //4.2 verify the signature
  //5. Key establishment using AF&BF
  //5.1 KC = SHA256(AF1||BF1)
  //5.2 KI = SHA256(AF2||BF2)

Node B(Client 2): 3.5.2 is completed

  //1.send over the cert & RB (plaintext form)
  //1.1 generate RB
  //1.2 send cert and RB
  //2.receive msg from peer, contains:
  //i) peer's cert
  //ii) ( AF1||AF2||RA||RB )encrypted by own cert's rsa public key
  //iii) (cert || AF1||AF2||RA||RB ) signed by peer's cert
  //3 Handle the Received Message (load PEER's cert & decrypt/verify message)
  //3.1 load PEER's cert & verify message
  //3.2.1 verify the cert. Is it signed by trusted CA?
  //3.2.2 Obtain the public key in the cert for verifying signature
  //3.3 decrypt message to get ( AF1||AF2||RA||RB )
  //3.4 verify the signature to validate msg ( AF1||AF2||RA||RB )
  //3.5 verify RB
  //3.5.1 extracted all the tokens first
  //3.5.2 verify RB
  //4. send  ( BF1 || BF2 || RA ) encrypted using A's cert || (BF1||BF2||RA) sign with own cert
  //5. Key establishment using AF&BF
  //5.1 KC = SHA256(AF1||BF1)
  //5.2 KI = SHA256(AF2||BF2)
