package org.bread_experts_group

import org.bread_experts_group.dns.DNSClass
import org.bread_experts_group.dns.DNSMessage
import org.bread_experts_group.dns.DNSOpcode
import org.bread_experts_group.dns.DNSQuestion
import org.bread_experts_group.dns.DNSType
import org.bread_experts_group.socket.read16ui
import org.bread_experts_group.socket.write16
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.util.logging.Logger
import kotlin.random.Random
import kotlin.system.exitProcess

data class DNSServerTest(
	val hostname: String,
	val ip: InetAddress,
	val tcp: Long?,
	val udp: Long?
)

fun main(args: Array<String>) {
	val logger = Logger.getLogger("DNS Client Main")
	logger.fine("- Argument read")
	val (singleArgs, multipleArgs) = readArgs(
		args,
		Flag("ip", default = "127.0.0.1"),
		Flag("port", default = 53, conv = ::stringToInt),
		Flag<String>("dns_root", repeatable = true),
		Flag("test_timeout", default = 2500, conv = ::stringToInt),
		Flag("dns_timeout", default = 2500, conv = ::stringToInt)
	)
	@Suppress("UNCHECKED_CAST")
	val rootServersRaw = multipleArgs["dns_root"] as? List<String>
	if (rootServersRaw == null || rootServersRaw.isEmpty()) {
		logger.severe("No root servers; cannot bootstrap DNS process")
		exitProcess(1)
	}
	val rootServers = rootServersRaw
		.parallelStream()
		.map {
			val (server, ipRaw) = it.split(':')
			val tag = "\"$server\" [$ipRaw]"
			val ip = InetAddress.getByName(ipRaw)
			logger.info("Resolution assertion of $tag")
			val query = DNSMessage.query(
				Random.nextInt() and 0xFFFF, DNSOpcode.QUERY,
				recursiveQuery = false, checkingDisabled = true,
				listOf(
					DNSQuestion(
						"$server.",
						DNSType.PTR__DOMAIN_POINTER, DNSClass.IN__INTERNET
					)
				)
			)
			val tcpTest = Socket().use { tcp ->
				tcp.keepAlive = false
				tcp.soTimeout = singleArgs.getValue("test_timeout") as Int
				tcp.tcpNoDelay = true
				try {
					val start = System.currentTimeMillis()
					tcp.connect(
						InetSocketAddress(ip, 53),
						singleArgs.getValue("test_timeout") as Int
					)
					ByteArrayOutputStream().use { dataStream ->
						query.write(dataStream)
						tcp.outputStream.write16(dataStream.size())
						tcp.outputStream.write(dataStream.toByteArray())
					}
					val data = tcp.inputStream.readNBytes(tcp.inputStream.read16ui())
					val time = System.currentTimeMillis() - start
					val response = DNSMessage.read(ByteArrayInputStream(data))
					if (response.transactionID != query.transactionID)
						throw SocketException("Server sent bad ID ${response.transactionID}")
					if (!response.reply)
						throw SocketException("Server didn't send reply?")
					time
				} catch(e: SocketException) {
					logger.warning("$tag TCP test failure: ${e.localizedMessage}")
					null
				} catch (_: SocketTimeoutException) {
					logger.warning("$tag TCP test failure: timed out [2500 ms]")
					null
				}
			}
			val udpTest = DatagramSocket().use { udp ->
				udp.soTimeout = singleArgs.getValue("test_timeout") as Int
				try {
					udp.connect(InetSocketAddress(ip, 53))
					ByteArrayOutputStream().use { dataStream ->
						query.write(dataStream)
						dataStream.toByteArray()
					}.let { data ->
						udp.send(DatagramPacket(data, data.size))
					}
					val parcel = DatagramPacket(ByteArray(512), 512)
					val start = System.currentTimeMillis()
					udp.receive(parcel)
					val time = System.currentTimeMillis() - start
					val response = DNSMessage.read(ByteArrayInputStream(parcel.data))
					if (response.transactionID != query.transactionID)
						throw SocketException("Server sent bad ID ${response.transactionID}")
					if (!response.reply)
						throw SocketException("Server didn't send reply?")
					time
				} catch (_: SocketTimeoutException) {
					logger.warning("$tag UDP test failure: timed out [2500 ms]")
					null
				}
			}
			DNSServerTest(
				server, ip,
				tcpTest, udpTest
			)
		}
		.toList()
	rootServers.forEach {
		logger.info("${it.hostname} ${it.tcp} ms / ${it.udp} ms")
	}
	logger.fine("- Socket retrieval & bind UDP (${singleArgs["port"]})")
	val udpSocket = DatagramSocket(
		InetSocketAddress(
			singleArgs["ip"] as String,
			singleArgs["port"] as Int
		)
	)
	logger.fine("- Socket retrieval & bind TCP (${singleArgs["port"]})")
	val tcpSocket = ServerSocket()
	tcpSocket.bind(
		InetSocketAddress(
			singleArgs["ip"] as String,
			singleArgs["port"] as Int
		)
	)
	logger.info("- Resolver start")
	Thread.ofPlatform().name("DNS UDP").start {
		while (true) {
			Thread.currentThread().name = "DNS-UDP"
			try {
				val packet = DatagramPacket(ByteArray(1500), 1500)
				udpSocket.receive(packet)
				Thread.currentThread().name = "UDP-${packet.socketAddress}"
				val localLogger = Logger.getLogger("DNS UDP ${packet.socketAddress}")
				val reply = resolverDns(
					localLogger,
					rootServers,
					packet.data.sliceArray(0..<packet.length),
					singleArgs
				)
				if (reply != null) {
					packet.setData(reply.second)
					udpSocket.send(packet)
				}
			} catch (e: Exception) {
				logger.severe { "UDP FAIL. ${e.stackTraceToString()}" }
			}
		}
	}
	Thread.ofPlatform().name("DNS TCP").start {
		while (true) {
			val socket = tcpSocket.accept()
			Thread.currentThread().name = "DNS-TCP"
			try {
				Thread.currentThread().name = "TCP-${socket.remoteSocketAddress}"
				val data = socket.inputStream.readNBytes(socket.inputStream.read16ui())
				val localLogger = Logger.getLogger("DNS TCP ${socket.remoteSocketAddress}")
				val reply = resolverDns(
					localLogger,
					rootServers,
					data,
					singleArgs
				)
				if (reply != null) {
					socket.outputStream.write16(reply.second.size)
					socket.outputStream.write(reply.second)
				}
			} catch (e: Exception) {
				logger.severe { "TCP FAIL. ${e.stackTraceToString()}" }
				socket.close()
			}
		}
	}
}