use std::convert::TryInto;
use tokio::net::UdpSocket;
// You might want a HashMap or similar to store player state on the client
use std::collections::HashMap;

// Define the mask bits consistently
const COORDS_MASK: u8 = 0x01; // Bit 0
const HEALTH_MASK: u8 = 0x02; // Bit 1
const XP_MASK: u8 = 0x04; // Bit 2
const ACHIEVEMENTS_MASK: u8 = 0x08; // Bit 3
const LEAVE_MASK: u8 = 0x20; // Bit 5 (Example)
