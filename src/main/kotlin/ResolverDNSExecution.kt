package org.bread_experts_group

import org.bread_experts_group.dns.DNSClass
import org.bread_experts_group.dns.DNSMessage
import org.bread_experts_group.dns.DNSOpcode
import org.bread_experts_group.dns.DNSQuestion
import org.bread_experts_group.dns.DNSResourceRecord
import org.bread_experts_group.dns.DNSType
import org.bread_experts_group.dns.readLabel
import org.bread_experts_group.socket.read16ui
import org.bread_experts_group.socket.write16
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.Stack
import java.util.logging.Logger
import kotlin.random.Random

fun udpSendQuery(data: ByteArray, to: InetAddress, timeout: Int): Pair<DNSMessage, ByteArray> = DatagramSocket().use {
	it.soTimeout = timeout
	val sendPacket = DatagramPacket(data, data.size, to, 53)
	it.send(sendPacket)
	val receivePacket = DatagramPacket(ByteArray(1024), 1024)
	it.receive(receivePacket)
	return DNSMessage.read(ByteArrayInputStream(receivePacket.data)) to
			receivePacket.data.sliceArray(0 until receivePacket.length)
}

fun tcpSendQuery(data: ByteArray, to: InetAddress, timeout: Int): Pair<DNSMessage, ByteArray> = Socket().use {
	it.soTimeout = timeout
	it.keepAlive = false
	it.connect(InetSocketAddress(to, 53), timeout)
	it.outputStream.write16(data.size)
	it.outputStream.write(data)
	val received = it.inputStream.readNBytes(it.inputStream.read16ui())
	return DNSMessage.read(ByteArrayInputStream(received)) to received
}

val cache: MutableMap<String, MutableMap<DNSType, MutableSet<Pair<DNSResourceRecord, Long>>>> = mutableMapOf()
fun saveCache(record: DNSResourceRecord) = cache
	.getOrPut(record.name) { mutableMapOf() }
	.getOrPut(record.rrType) { mutableSetOf() }
	.add(record to System.nanoTime() + record.timeToLive * 1000000)
fun getCache(name: String, type: DNSType) = cache
	.getOrPut(name) { mutableMapOf() }
	.getOrPut(type) { mutableSetOf() }
	.let { rrs ->
		rrs.removeAll { System.nanoTime() > it.second }
		rrs.randomOrNull()?.first
	}

fun dnsResolution(
	logger: Logger,
	servers: List<DNSServerTest>,
	data: ByteArray,
	immediate: InetAddress,
	singleArgs: SingleArgs
): Pair<DNSMessage, ByteArray>? {
	val query = DNSMessage.read(ByteArrayInputStream(data))
	val responsible = Stack<InetAddress>()
	responsible.push(immediate)
	val timeout = singleArgs.getValue("dns_timeout") as Int
	while (responsible.isNotEmpty()) {
		val thisServer = responsible.pop()
		val (message, data) = try {
			val initial = udpSendQuery(data, thisServer, timeout)
			if (initial.first.truncated) tcpSendQuery(data, thisServer, timeout)
			else initial
		} catch (_: SocketTimeoutException) {
			continue
		}
		logger.fine { message.toString() }
		message.answers.forEach(::saveCache)
		message.authorityRecords.forEach(::saveCache)
		message.additionalRecords.forEach(::saveCache)
		if (message.answers.isNotEmpty() || message.authoritative) {
			message.answers.firstOrNull()?.let { a ->
				if (
					a.rrType == DNSType.CNAME__CANONICAL_NAME &&
					query.questions.first { q -> q.name == a.name }.qType != DNSType.CNAME__CANONICAL_NAME
				) {
					val resent = dnsResolution(
						logger,
						servers,
						ByteArrayOutputStream().use {
							DNSMessage.query(
								0x5E53, DNSOpcode.QUERY,
								recursiveQuery = false, checkingDisabled = false,
								listOf(
									DNSQuestion(
										readLabel(ByteArrayInputStream(a.rrData), data),
										DNSType.A__IPV4_ADDRESS, DNSClass.IN__INTERNET
									)
								)
							).write(it)
							it.toByteArray()
						},
						immediate,
						singleArgs
					)
					if (resent == null) return null
					val reparsed = DNSMessage.reply(
						query.transactionID, null, resent.first.opcode,
						resent.first.authoritative, resent.first.authenticData,
						resent.first.recursionAvailable, resent.first.responseCode,
						resent.first.questions, resent.first.answers,
						resent.first.authorityRecords, resent.first.additionalRecords
					)
					return reparsed to ByteArrayOutputStream().use {
						reparsed.write(it)
						it.toByteArray()
					}
				}
			}
			return message to data
		}
		message.authorityRecords.filter { it.rrType == DNSType.NS__NAME_SERVER }.map {
			readLabel(
				ByteArrayInputStream(it.rrData),
				data
			)
		}.forEach { nextAuthority ->
			while (true) {
				val found = getCache(nextAuthority, DNSType.A__IPV4_ADDRESS)
				if (found != null) {
					responsible.push(InetAddress.getByAddress(found.rrData))
					break
				} else {
					resolverDns(
						logger,
						servers,
						ByteArrayOutputStream().use {
							DNSMessage.query(
								0x13A4, DNSOpcode.QUERY,
								recursiveQuery = false, checkingDisabled = false,
								listOf(
									DNSQuestion(nextAuthority, DNSType.A__IPV4_ADDRESS, DNSClass.IN__INTERNET)
								)
							).write(it)
							it.toByteArray()
						},
						singleArgs
					)
				}
			}
		}
	}
	return null
}

fun resolverDns(
	logger: Logger,
	servers: List<DNSServerTest>,
	data: ByteArray,
	singleArgs: SingleArgs
): Pair<DNSMessage, ByteArray>? {
	val sorted = servers
		.filter { it.udp != null }
		.sortedBy { it.udp }
	(sorted.firstOrNull { Random.nextBoolean() } ?: sorted.last()).let { selected ->
		return dnsResolution(logger, servers, data, selected.ip, singleArgs)
	}
}