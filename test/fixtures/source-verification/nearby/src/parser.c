int parse_packet(const char *packet) {
  if (packet == NULL) {
    return ERROR_INVALID;
  }
  return decode_checked(packet);
}
