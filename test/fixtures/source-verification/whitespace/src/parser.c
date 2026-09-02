int parse_packet(const char *packet) {
	if (packet == 0) {
		return -1;
	}
	return     decode_checked(packet);
}
