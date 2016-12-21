# Rare TCP state 



### [TCP State Machine](http://seller.shopee.sg/api/v1/cdn_proxy/621ad36e32ae0d7a58f1082a7bebd15f)

![TCP](http://seller.shopee.sg/api/v1/cdn_proxy/621ad36e32ae0d7a58f1082a7bebd15f)


### Normal State
>| Client| Server |
| ------------- | ----------- |
| closed | closed 
| closed  | listen
| (***SYN***)  | 
| syn_sent |  syn_received
| |(***SYN, ACK***)  | 
| established |  
| (***ACK***)  | 
| established |  established

| Client| Server |
| ------------- | ----------- |
| established |  established
| (***DATA***) <===|===>(***DATA***)  
| established |  established


>| Client| Server |
| ------------- | ----------- |
| (***FIN***) | 
| fin_wait1| 
|  | (***ACK***)
| fin_wait2 |  close_wait
| (***DATA***) <---|---(***DATA***)  
| | (***FIN***)
| | last_ack
| (***ACK***) | 
| time_wait | closed
| closed | closed


[Ref : TCP/IP State Transition Diagram](https://www.doc.ic.ac.uk/~maffeis/331/TCP-Diagram.pdf)



##Rare State1


### Circumstance
 **One-way communication**
* Server only read from socket, no response.
* Client only write data into socket, ignore response.
* Server will close an connection after been idle for Xmins

### [Demo](http://git.garena.com/tangro/Demo/tree/master/demo1)
```golang
func handleRequest(conn net.Conn) {
    buf := make([]byte, 1024)

    //defer conn.(*net.TCPConn).CloseWrite()  // ShutDown(SHUT_WR)
    //defer conn.(*net.TCPConn).CloseRead() // ShutDown(SHUT_RD)
    defer conn.Close()
    for {
        conn.SetReadDeadline(time.Now().Add(10 * time.Second))
        reqLen, err := conn.Read(buf)
        if err != nil {
            DoLog("Error in reading[%v]", err.Error())
            return
        } else {
            DoLog("INFO read[%v] Message[%v]", reqLen, string(buf))
        }   

        //conn.Write([]byte("Message received."))
    }   
}

```

Result
![](http://a.hiphotos.baidu.com/image/pic/item/810a19d8bc3eb135db4d3c17ae1ea8d3fc1f4490.jpg)

We got a data loss here.

### Rare State1 CLOSE_WAITE
* do conn.Write() with a []byte -> it runs fine without error!
* it takes another conn.Write to get the error: broken pipe
* **[Data Loss]()**



### what we expected :
> [***fin_wait2*** (Server)| ***close_wait*** (Client)]()
>| (***DATA***) <-------------|----------(***DATA***)  

### Why only one data lost?
```
21:13:03.505439 IP 127.0.0.1.5555 > 127.0.0.1.6882: Flags [F.], seq 1, ack 4, win 256, options [nop,nop,TS val 1996918705 ecr 1996913703], length 0
21:13:03.506316 IP 127.0.0.1.6882 > 127.0.0.1.5555: Flags [.], ack 2, win 257, options [nop,nop,TS val 1996918706 ecr 1996918705], length 0
21:13:06.783940 IP 127.0.0.1.6882 > 127.0.0.1.5555: Flags [P.], seq 4:5, ack 2, win 257, options [nop,nop,TS val 1996921983 ecr 1996918705], length 1
21:13:06.783975 IP 127.0.0.1.5555 > 127.0.0.1.6882: Flags [R], seq 4031687754, win 0, length 0
```


### Close vs. Shutdown
The normal way to terminate a network connection is to call the close function. But, there are two limitations with close that can be avoided with shutdown:

>     Close() terminates both directions of data transfer, reading and writing. 
>Since a TCP connection is full-duplex , there are times when we want to tell the other end that we have finished sending, even though that end might have more data to send us. 


>      Close() only terminates socket when the fd reference is 0
>close() decrements the descriptor's reference count and closes the socket only if the count reaches 0.     shutdown() breaks the connection for all processes sharing the socketid.  Those who try to read will detect EOF, and those who try to write will reseive SIGPIPE,

[REF shutdown Function](http://flylib.com/books/en/3.225.1.97/1/)




####NOTE: A shutdown will not close a socket.
>It's important to note that shutdown() doesn't actually close the file descriptor—it just changes its usability. To free a socket descriptor, you need to use close().

[shutdown, close and linger](http://d.hiphotos.baidu.com/image/pic/item/4bed2e738bd4b31cc4ab66178fd6277f9f2ff883.jpg)
![](http://d.hiphotos.baidu.com/image/pic/item/4bed2e738bd4b31cc4ab66178fd6277f9f2ff883.jpg)



The effect of an setsockopt(..., SO_LINGER,...) depends on what the values in the linger structure (the third parameter passed to setsockopt()) are:
>     Case 1:  linger->l_onoff is zero (linger->l_linger has no meaning): 
 This is the default.
On close(), the underlying stack attempts to gracefully shutdown the connection after ensuring all unsent data is sent. In the case of connection-oriented protocols such as TCP, the stack also ensures that sent data is acknowledged by the peer.  The stack will perform the above-mentioned graceful shutdown in the background (after the call to close() returns), regardless of whether the socket is blocking or non-blocking.

>     Case 2: linger->l_onoff is non-zero and linger->l_linger is zero:
A close() returns immediately. The underlying stack discards any unsent data, and, in the case of connection-oriented protocols such as TCP, sends a RST (reset) to the peer (this is termed a hard or abortive close). All subsequent attempts by the peer's application to read()/recv() data will result in an ECONNRESET.

>     Case 3: linger->l_onoff is non-zero and linger->l_linger is non-zero:
A close() will either block (if a blocking socket) or fail with EWOULDBLOCK (if non-blocking) until a graceful shutdown completes or the time specified in linger->l_linger elapses (time-out). Upon time-out the stack behaves as in case 2 above.


### How to get one-way communication:
CloseWrite (Shutdown) instead of Close()
Demo




[REF close linger](http://www.evernote.com/l/APtUKgBdpYJH4KFhQFuTzVMnTWkUYzNwC3k/)
[REF Writing to a closed, local TCP socket not failing](http://stackoverflow.com/questions/11436013/writing-to-a-closed-local-tcp-socket-not-failing)
[REF When should I use shutdown()](http://www.unixguide.net/network/socketfaq/2.6.shtml)
[REF Beej's Guide to Network Programming](http://beej.us/guide/bgnet/output/html/singlepage/bgnet.html#closedown)
[REF close vs shutdown socket?](http://stackoverflow.com/questions/4160347/close-vs-shutdown-socket)
[REF The ultimate SO_LINGER page, or: why is my tcp not reliable](http://blog.csdn.net/CPP_CHEN/article/details/29864509)

[Go语言TCP Socket编程](http://tonybai.com/2015/11/17/tcp-programming-in-golang/)
[socket链接的关闭close和shutdown的区别_TIME_WAIT和CLOSE_WAIT什么时刻出现_如何处理](http://blog.csdn.net/liuhongxiangm/article/details/11700277)
[socket关闭: close()和shutdown()的差异](http://drmingdrmer.github.io/tech/programming/network/2015/07/28/close-shutdown.html)



### How to prevent the data loss
* Check Connection Closed before write.
* Socket Read in golang is block (underlying socket in Go Runtime is Non-block socket + epool)
[The Go scheduler](https://morsmachine.dk/go-scheduler)

```
func CheckFdCloseWait(conn *net.TCPConn) (flag bool) {
    fileDesc, errFile := conn.File()
    if nil != errFile {
        return false
    }   
    msg := make([]byte, 0)
    nRead, _, err := syscall.Recvfrom(int(fileDesc.Fd()), msg, syscall.MSG_DONTWAIT)

    DoLog("CheckFdCloseWait nRead[%v] err[%v]", nRead, err)
    if nil == err && nRead == 0 { 
        return true
    }   
    return false
}
```
DEMO





##Rare State 2

### Circumstance
* Server listen on port with default backlog.
* Client initial a large number of connect at the same time.


###Demo
```
sudo netstat -nap  | grep -w '5555' | awk '{print $6" "$7}' | sort | uniq -c
      1 LISTEN 20310/./Server
    125 ESTABLISHED -
     27 ESTABLISHED 20310/./Server
     69 SYN_RECV -
    221 ESTABLISHED 59253/./ClientSend
     79 SYN_SENT 59253/./ClientSend
     
sudo netstat -nap  | grep -w '5555' | awk '{print $6" "$7}' | sort | uniq -c
     54 ESTABLISHED -
    138 ESTABLISHED 20310/./Server
    300 ESTABLISHED 59253/./ClientSend
      1 LISTEN 20310/./Server
```


### State
After a massive current connect (with a relatively small backlog)
> [***ESTABLISH*** (Client)| ***NULL*** (Server)]()


### [Fix](https://forum.garenanow.com/d/102-fake-tcp-connections-caused-by-syn-cookies)

Solutions

* Disable SYN cookies
For security reason, we don't want to do this.
* Increase the backlog size of listen socket.
/proc/sys/net/ipv4/tcp_max_syn_backlog, default 2048, change to 8192
/proc/sys/net/core/somaxconn, default 128, change to 4096

sudo tail -f /var/log/messages

### Backlog

>     man listen
* backlog ... it specifies the queue length for [completely  established  sockets]()  waiting to be accepted, instead of the number of incomplete connection requests.
* If the backlog argument is greater than the value in **/proc/sys/net/core/somaxconn**, then it is  silently  truncated to  that  value;  the  default  value  in this file is 128.   ...
*       The maximum length of the queue for [incomplete sockets]() can be  set  using  **/proc/sys/net/ipv4/tcp_max_syn_backlog**.
       When  syncookies  are enabled there is no logical maximum length and this setting is ignored.  See tcp(7) for more information.


This means that current Linux versions use two distinct queues: 

* a SYN queue with a size specified by a system wide setting and 
* **SYN_RECV [cona1, cona2, cona3 ... ]**
* an accept queue with a size specified by the application.
* **ESTABLISHED [conb1, conb2, conb3 ... ]**




### [SYN cookies](https://en.wikipedia.org/wiki/SYN_cookies)

>from wikipedia:
>SYN cookie is a technique used to resist SYN flood attacks. ... ... defines SYN cookies as ["particular choices of initial TCP sequence numbers by TCP servers." ]()
> 
>In particular, the use of SYN cookies allows a server to avoid dropping connections **when the SYN queue fills up**. Instead, the server behaves as if the SYN queue had been enlarged. 
>
>The server sends back the appropriate SYN+ACK response to the client but **discards the SYN queue entry**. 

>If the server then receives a subsequent ACK response from the client, the **server is able to reconstruct the SYN queue entry** using information encoded in the TCP sequence number.

### How the cookie is generated
[net/ipv4/syncookies.c](http://lxr.free-electrons.com/source/net/ipv4/syncookies.c)
![](http://h.hiphotos.baidu.com/image/pic/item/d000baa1cd11728b482e168fc0fcc3cec3fd2c1f.jpg)



[How TCP backlog works in Linux](http://veithen.github.io/2014/01/01/how-tcp-backlog-works-in-linux.html)
[TCP SYN Cookies – DDoS defence](http://etherealmind.com/tcp-syn-cookies-ddos-defence/)
[Quick Blind TCP Connection Spoofing with SYN Cookies](http://www.jakoblell.com/blog/2013/08/13/quick-blind-tcp-connection-spoofing-with-syn-cookies/)

#Question

* SynCookie can rebuild the connection , but in demo it did not.
* Can not find any warn log in dmesg or /var/log/messages
* The SYN_RECEIVE queue is not full
* SYN_RECV < SYN_SENT 
```
sudo netstat -nap  | grep -w '5555' | awk '{print $6" "$7}' | sort | uniq -c
      1 LISTEN 20310/./Server
    125 ESTABLISHED -
     27 ESTABLISHED 20310/./Server
     69 SYN_RECV -
    221 ESTABLISHED 59253/./ClientSend
     79 SYN_SENT 59253/./ClientSend
     
sudo netstat -nap  | grep -w '5555' | awk '{print $6" "$7}' | sort | uniq -c
     54 ESTABLISHED -
    138 ESTABLISHED 20310/./Server
    300 ESTABLISHED 59253/./ClientSend
      1 LISTEN 20310/./Server
```

### Did SynCookie take effect?
Demo
SynCookie is not triggered


### Why Syn Cookie did not work?
The SYN_RECEIVE queue is not full



### [Ack Missing](http://e.hiphotos.baidu.com/image/pic/item/3bf33a87e950352a724ab3a55b43fbf2b2118b70.jpg)
Demo
![](http://e.hiphotos.baidu.com/image/pic/item/3bf33a87e950352a724ab3a55b43fbf2b2118b70.jpg)


>| Client| Server |
| ------------- | ----------- |
| closed | closed 
| closed  | listen
| (***SYN***)  | 
| syn_sent |  syn_received
| |(***SYN, ACK***)  | 
| established |  
| [(***ACK***)missing]()  | 
| established |  established



### Why

```
1257 /*
1258  * The three way handshake has completed - we got a valid synack -
1259  * now create the new socket.
1260  */
1261 struct sock *tcp_v4_syn_recv_sock(const struct sock *sk, struct sk_buff *skb,
1262                                   struct request_sock *req,
1263                                   struct dst_entry *dst,
1264                                   struct request_sock *req_unhash,
1265                                   bool *own_req)
1266 {
1267         struct inet_request_sock *ireq;
1268         struct inet_sock *newinet;
1269         struct tcp_sock *newtp;
1270         struct sock *newsk;
1271 #ifdef CONFIG_TCP_MD5SIG
1272         struct tcp_md5sig_key *key;
1273 #endif
1274         struct ip_options_rcu *inet_opt;
1275 
1276         if (sk_acceptq_is_full(sk))
1277                 goto exit_overflow;
```

* The code after the exit_overflow label will perform some cleanup, update the ListenOverflows and ListenDrops statistics in /proc/net/netstat and then return NULL. 
* This will trigger the execution of the **listen_overflow ** code in **tcp_check_req**:
```
774 listen_overflow:
775         if (!sysctl_tcp_abort_on_overflow) {
776                 inet_rsk(req)->acked = 1;
777                 return NULL;
778         }


```
>This means that unless /proc/sys/net/ipv4/tcp_abort_on_overflow is set to 1 (in which case the code right after the code shown above will send a RST packet),  the implementation basically does… nothing!



To summarize, if the TCP implementation in Linux receives the ACK packet of the 3-way handshake and the accept queue is full, it will  basically [ignore that packet ]() . 



### SYN_RECV not full &&  SYN_RECV < SYN_SENT 
```
sudo netstat -nap  | grep -w '5555' | awk '{print $6" "$7}' | sort | uniq -c
      1 LISTEN 20310/./Server
    125 ESTABLISHED -
     27 ESTABLISHED 20310/./Server
     69 SYN_RECV -
    221 ESTABLISHED 59253/./ClientSend
     79 SYN_SENT 59253/./ClientSend

```
The reason is the following code in the tcp_v4_conn_request function (which does the processing of SYN packets) in net/ipv4/tcp_ipv4.c:
```
		/* Accept backlog is full. If we have already queued enough
         * of warm entries in syn queue, drop request. It is better than
         * clogging syn queue with openreqs with exponentially increasing
         * timeout.
         */
        if (sk_acceptq_is_full(sk) && inet_csk_reqsk_queue_young(sk) > 1) {
                NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_LISTENOVERFLOWS);
                goto drop;
        }    
```
 
What this means is that if the accept queue is full, then the kernel will impose a limit on the rate at which SYN packets are accepted. If too many SYN packets are received, some of them will be dropped. In this case, it is up to the client to retry sending the SYN packet 