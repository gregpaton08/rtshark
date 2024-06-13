//! An interface to [TShark], the famous network protocol analyzer. [TShark] is a part of [Wireshark] distribution.
//! This crate provides an API to start TShark and analyze it's output.
//! It lets you capture packet data from a live network, or read packets from a previously saved capture file, printing a decoded form of those packets.
//! TShark's native capture file format is pcapng format, which is also the format used by Wireshark and various other tools.
//!
//! [Wireshark]: <https://www.wireshark.org/>
//! [TShark]: <https://www.wireshark.org/docs/man-pages/tshark.html>
//!
//! Many information about TShark usage could also be found [here](https://tshark.dev/).
//!
//! TShark application must be installed for this crate to work properly.
//!
//! This crates supports both offline processing (using pcap file) and live analysis (using an interface or a fifo).
//!
//! # Examples
//!
//! ```
//! // Creates a builder with needed tshark parameters
//! let builder = rtshark::RTSharkBuilder::builder()
//!     .input_path("/tmp/my.pcap");
//!
//! // Start a new TShark process
//! let mut rtshark = match builder.spawn() {
//!     Err(err) =>  { eprintln!("Error running tshark: {err}"); return }
//!     Ok(rtshark) => rtshark,
//! };
//!
//! // read packets until the end of the PCAP file
//! while let Some(packet) = rtshark.read().unwrap_or_else(|e| {
//!     eprintln!("Error parsing TShark output: {e}");
//!     None
//! }) {
//!     for layer in packet {
//!         println!("Layer: {}", layer.name());
//!         for metadata in layer {
//!             println!("\t{}", metadata.display());
//!         }
//!     }
//! }
//! ```

use quick_xml::events::{BytesStart, Event};
use std::io::{BufRead, BufReader, Error, ErrorKind, Result};
#[cfg(target_family = "unix")]
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, ChildStderr, ChildStdout, Command, Stdio};

/// A metadata belongs to one [Layer]. It describes one particular information about a [Packet] (example: IP source address).
#[derive(Default, Clone, Debug, PartialEq)]
pub struct Metadata {
    /// Name displayed by TShark
    name: String,
    /// Value displayed by TShark, in a human readable format
    /// It uses pyshark-like algorithm to display the best 'value' :
    /// it looks for "show" first, then "value", finally "showname"
    value: String,
    /// Value read by TShark, in hex format
    raw_value: String,
    /// Both name and value, as displayed by thshark
    display: String,
    /// Size of this data extracted from packet header protocol, in bytes
    size: u32,
    /// Offset of this data in the packet, in bytes
    position: u32,
    /// true if the hide attribute is set to yes, otherwise false.
    hide: bool,
}

/// This is one metadata from a given layer of the packet returned by TShark application.
impl Metadata {
    /// Creates a new metadata. This function is useless for most applications.
    pub fn new(
        name: String,
        value: String,
        raw_value: String,
        display: String,
        size: u32,
        position: u32,
        hide: bool,
    ) -> Metadata {
        Metadata {
            name,
            value,
            raw_value,
            display,
            size,
            position,
            hide,
        }
    }

    /// Get the name of this metadata. The name is returned by TShark.
    ///
    /// # Examples
    ///
    /// ```
    /// let ip_src = rtshark::Metadata::new("ip.src".to_string(), "127.0.0.1".to_string(), "Source: 127.0.0.1".to_string(), 4, 12);
    /// assert_eq!(ip_src.name(), "ip.src")
    /// ```
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Value for this metadata, displayed by TShark, in a human readable format.
    /// It uses pyshark-like algorithm to display the best 'value' :
    /// it looks for "show" first, then "value", finally "showname".
    ///
    /// # Examples
    ///
    /// ```
    /// let ip_src = rtshark::Metadata::new("ip.src".to_string(), "127.0.0.1".to_string(), "Source: 127.0.0.1".to_string(), 4, 12);
    /// assert_eq!(ip_src.value(), "127.0.0.1")
    /// ```
    pub fn value(&self) -> &str {
        self.value.as_str()
    }

    /// Value read by TShark, in hex format
    ///
    /// # Examples
    ///
    /// ```
    /// let ip_src = rtshark::Metadata::new("ip.src".to_string(), "127.0.0.1".to_string(), "3132372e302e302e31".to_string(), "Source: 127.0.0.1".to_string(), 4, 12);
    /// assert_eq!(ip_src.raw_value(), "3132372e302e302e31")
    /// ```
    pub fn raw_value(&self) -> &str {
        self.raw_value.as_str()
    }

    /// Both name and value, as displayed by TShark
    ///
    /// # Examples
    ///
    /// ```
    /// let ip_src = rtshark::Metadata::new("ip.src".to_string(), "127.0.0.1".to_string(), "Source: 127.0.0.1".to_string(), 4, 12);
    /// assert_eq!(ip_src.display(), "Source: 127.0.0.1")
    /// ```
    pub fn display(&self) -> &str {
        self.display.as_str()
    }

    /// Size of this data extracted from packet header protocol, in bytes
    ///
    /// # Examples
    ///
    /// ```
    /// let ip_src = rtshark::Metadata::new("ip.src".to_string(), "127.0.0.1".to_string(), "Source: 127.0.0.1".to_string(), 4, 12);
    /// assert_eq!(ip_src.size(), 4)
    /// ```
    pub fn size(&self) -> u32 {
        self.size
    }

    /// Offset of this data in the packet, in bytes
    ///
    /// # Examples
    ///
    /// ```
    /// let ip_src = rtshark::Metadata::new("ip.src".to_string(), "127.0.0.1".to_string(), "Source: 127.0.0.1".to_string(), 4, 12);
    /// assert_eq!(ip_src.position(), 12)
    /// ```
    pub fn position(&self) -> u32 {
        self.position
    }

    pub fn hide(&self) -> bool {
        self.hide
    }
}

/// A layer is a protocol in the protocol stack of a packet (example: IP layer). It may contain multiple [Metadata].
#[derive(Default, Clone, Debug, PartialEq)]
pub struct Layer {
    /// Name of this layer
    name: String,
    /// Number of this layer for this packet in the stack of layers. Starts at 0 with "frame" virtual layer.
    index: usize,
    /// List of metadata associated to this layer
    metadata: Vec<Metadata>,
    /// The size of the layer in bytes.
    size: usize,
    /// Offset of this data in the packet, in bytes
    position: u32,
}

impl Layer {
    /// Creates a new layer. This function is useless for most applications.
    ///
    /// # Example
    ///
    /// ```
    /// let ip_layer = rtshark::Layer::new("ip".to_string(), 1, 20);
    /// ```
    pub fn new(name: String, index: usize, size: usize, position: u32) -> Self {
        Layer {
            name,
            index,
            metadata: vec![],
            size,
            position,
        }
    }
    /// Retrieves the layer name of this layer object. This name is a protocol name returned by TShark.
    ///
    /// # Example
    ///
    /// ```
    /// let mut ip_layer = rtshark::Layer::new("ip".to_string(), 1);
    /// assert_eq!(ip_layer.name(), "ip")
    /// ```
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Retrieves this layer index (number of this layer in the stack of the packet's layers).
    ///
    /// # Example
    ///
    /// ```
    /// let mut ip_layer = rtshark::Layer::new("ip".to_string(), 1);
    /// assert_eq!(ip_layer.index(), 1)
    /// ```
    pub fn index(&self) -> usize {
        self.index
    }

    /// Retrieves the layer's size in bytes.
    ///
    /// # Example
    ///
    /// ```
    /// let mut ip_layer = rtshark::Layer::new("ip".to_string(), 1, 36);
    /// assert_eq!(ip_layer.size(), 36)
    /// ```
    pub fn size(&self) -> usize {
        self.size
    }

    /// Offset of this layer in the packet, in bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut ip_layer = rtshark::Layer::new("ip".to_string(), 1, 36, 14);
    /// assert_eq!(ip_layer.position(), 14)
    /// ```
    pub fn position(&self) -> u32 {
        self.position
    }

    /// Adds a metadata in the list of metadata for this layer. This function is useless for most applications.
    ///
    /// # Example
    ///
    /// ```
    /// let mut ip_layer = rtshark::Layer::new("ip".to_string(), 1);
    /// let ip_src = rtshark::Metadata::new("ip.src".to_string(), "127.0.0.1".to_string(), "Source: 127.0.0.1".to_string(), 4, 12);
    /// ip_layer.add(ip_src);
    /// ```
    pub fn add(&mut self, metadata: Metadata) {
        self.metadata.push(metadata);
    }

    /// Get a metadata by its name.
    ///
    /// # Example
    ///
    /// ```
    /// let mut ip_layer = rtshark::Layer::new("ip".to_string(), 1);
    /// let ip_src = rtshark::Metadata::new("ip.src".to_string(), "127.0.0.1".to_string(), "Source: 127.0.0.1".to_string(), 4, 12);
    /// ip_layer.add(ip_src);
    /// let ip_src = ip_layer.metadata("ip.src").unwrap();
    /// assert_eq!(ip_src.display(), "Source: 127.0.0.1")
    /// ```
    pub fn metadata(&self, name: &str) -> Option<&Metadata> {
        self.metadata.iter().find(|m| m.name().eq(name))
    }

    /// Get an iterator on the list of [Metadata] for this [Layer].
    /// This iterator does not take ownership of returned [Metadata].
    /// This is the opposite of the "into"-iterator which returns owned objects.
    ///
    /// # Example
    ///
    /// ```
    /// let mut ip_layer = rtshark::Layer::new("ip".to_string(), 1);
    /// let ip_src = rtshark::Metadata::new("ip.src".to_string(), "127.0.0.1".to_string(), "Source: 127.0.0.1".to_string(), 4, 12);
    /// ip_layer.add(ip_src);
    /// let metadata = ip_layer.iter().next().unwrap();
    /// assert_eq!(metadata.display(), "Source: 127.0.0.1")
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = &Metadata> {
        self.metadata.iter()
    }
}

impl IntoIterator for Layer {
    type Item = Metadata;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    /// Get an "into" iterator on the list of [Metadata] for this [Layer].
    /// This iterator takes ownership of returned [Metadata].
    /// This is the opposite of an iterator by reference.
    ///
    /// # Example 1
    ///
    /// ```
    /// let mut ip_layer = rtshark::Layer::new("ip".to_string(), 1);
    /// let ip_src = rtshark::Metadata::new("ip.src".to_string(), "127.0.0.1".to_string(), "Source: 127.0.0.1".to_string(), 4, 12);
    /// ip_layer.add(ip_src);
    /// for metadata in ip_layer {
    ///     assert_eq!(metadata.display(), "Source: 127.0.0.1")
    /// }
    /// ```
    /// # Example 2
    ///
    /// ```
    /// # let mut ip_layer = rtshark::Layer::new("ip".to_string(), 1);
    /// # let ip_src = rtshark::Metadata::new("ip.src".to_string(), "127.0.0.1".to_string(), "Source: 127.0.0.1".to_string(), 4, 12);
    /// # ip_layer.add(ip_src);
    /// let metadata = ip_layer.into_iter().next().unwrap();
    /// assert_eq!(metadata.display(), "Source: 127.0.0.1")
    /// ```
    fn into_iter(self) -> Self::IntoIter {
        self.metadata.into_iter()
    }
}

/// The [Packet] object represents a network packet, a formatted unit of data carried by a packet-switched network. It may contain multiple [Layer].
#[derive(Default, Clone, Debug, PartialEq)]
pub struct Packet {
    /// Stack of layers for a packet
    layers: Vec<Layer>,
    /// Packet capture timestamp --- the number of non-leap-microseconds since
    /// January 1, 1970 UTC
    timestamp_micros: Option<i64>,
    /// The size of the layer.
    pub size: usize,
}

impl Packet {
    /// Creates a new empty layer. This function is useless for most applications.
    /// # Examples
    ///
    /// ```
    /// let packet = rtshark::Packet::new();
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns this packet's capture time as the number of non-leap-microseconds since
    /// January 1, 1970 UTC.
    pub fn timestamp_micros(&self) -> Option<i64> {
        self.timestamp_micros
    }

    /// Push a new layer at the end of the layer stack. This function is useless for most applications.
    /// # Examples
    ///
    /// ```
    /// let mut ip_packet = rtshark::Packet::new();
    /// ip_packet.push("ip".to_string());
    /// ```
    pub fn push(&mut self, name: String, size: usize, position: u32) {
        let layer = Layer::new(name, self.layers.len(), size, position);
        self.layers.push(layer);
    }

    /// Push a new layer at the end of the layer stack if the given layer does not exist yet.
    pub fn push_if_not_exist(&mut self, name: String, size: usize, position: u32) {
        if let Some(last_layer) = self.last_layer_mut() {
            // ignore the layer if it already exists
            if last_layer.name.eq(&name) {
                return;
            }
        }

        self.push(name, size, position);
    }

    /// Get the last layer as mutable reference. It is used to push incoming metadata in the current packet.
    fn last_layer_mut(&mut self) -> Option<&mut Layer> {
        self.layers.last_mut()
    }

    /// Get the layer for the required index. Indexes start at 0.
    /// # Examples
    ///
    /// ```
    /// let mut ip_packet = rtshark::Packet::new();
    /// ip_packet.push("eth".to_string());
    /// ip_packet.push("ip".to_string());
    /// ip_packet.push("tcp".to_string());
    /// assert_eq!(ip_packet.layer_index(0).unwrap().name(), "eth");
    /// assert_eq!(ip_packet.layer_index(1).unwrap().name(), "ip");
    /// assert_eq!(ip_packet.layer_index(2).unwrap().name(), "tcp");
    /// ```
    pub fn layer_index(&self, index: usize) -> Option<&Layer> {
        self.layers.get(index)
    }

    /// Get the layer with the searched name.
    /// If multiple layers have the same name, in case of IP tunnels for instance, the layer with the lowest index is returned.
    /// # Examples
    ///
    /// ```
    /// let mut ip_packet = rtshark::Packet::new();
    /// ip_packet.push("eth".to_string());
    /// ip_packet.push("ip".to_string());
    /// ip_packet.push("ip".to_string());
    /// let ip_layer = ip_packet.layer_name("ip").unwrap();
    /// assert_eq!(ip_layer.index(), 1);
    /// ```
    pub fn layer_name(&self, name: &str) -> Option<&Layer> {
        self.layers.iter().find(|&layer| layer.name.eq(name))
    }

    /// Get the number of layers for this packet.
    /// # Examples
    ///
    /// ```
    /// let mut ip_packet = rtshark::Packet::new();
    /// ip_packet.push("eth".to_string());
    /// ip_packet.push("ip".to_string());
    /// ip_packet.push("tcp".to_string());
    /// assert_eq!(ip_packet.layer_count(), 3);
    /// ```
    pub fn layer_count(&self) -> usize {
        self.layers.len()
    }

    /// Get an iterator on the list of [Layer] for this [Packet].
    /// This iterator does not take ownership of returned data.
    /// This is the opposite of the "into"-iterator which returns owned objects.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut ip_packet = rtshark::Packet::new();
    /// ip_packet.push("ip".to_string());
    /// let layer = ip_packet.iter().next().unwrap();
    /// assert_eq!(layer.name(), "ip")
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = &Layer> {
        self.layers.iter()
    }
}

impl IntoIterator for Packet {
    type Item = Layer;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    /// Get an "into" iterator on the list of [Layer] for this [Packet].
    /// This iterator takes ownership of returned [Layer].
    /// This is the opposite of an iterator by reference.
    ///
    /// # Example 1
    ///
    /// ```
    /// let mut ip_packet = rtshark::Packet::new();
    /// ip_packet.push("ip".to_string());
    /// for layer in ip_packet {
    ///     assert_eq!(layer.name(), "ip")
    /// }
    /// ```
    /// # Example 2
    ///
    /// ```
    /// let mut ip_packet = rtshark::Packet::new();
    /// ip_packet.push("ip".to_string());
    /// let layer = ip_packet.into_iter().next().unwrap();
    /// assert_eq!(layer.name(), "ip")
    /// ```
    fn into_iter(self) -> Self::IntoIter {
        self.layers.into_iter()
    }
}

/// RTSharkBuilder is used to prepare arguments needed to start a TShark instance.
/// When the mandatory input_path is set, it creates a [RTSharkBuilderReady] object,
/// which can be used to add more optional parameters before spawning a [RTShark] instance.
pub struct RTSharkBuilder {}

impl<'a> RTSharkBuilder {
    /// Initial builder function which creates an empty object.
    pub fn builder() -> Self {
        RTSharkBuilder {}
    }

    /// This is the only mandatory parameter, used to provide source of packets.
    /// It enables either -r or -i option of TShark, depending on the use of .live_capture(), see below.
    ///
    /// # Without .live_capture()
    ///
    /// If .live_capture() is not set, TShark will read packet data from a file. It can be any supported capture file format (including gzipped files).
    ///
    /// It is possible to use named pipes or stdin (-) here but only with certain (not compressed) capture file formats
    /// (in particular: those that can be read without seeking backwards).
    ///
    /// ## Example: Prepare an instance of TShark to read a PCAP file
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/my.pcap");
    /// ```
    ///
    /// # With .live_capture()
    ///
    /// If .live_capture() is set, a network interface or a named pipe can be used to read packets.
    ///
    /// Network interface names should match one of the names listed in "tshark -D" (described above);
    /// a number, as reported by "tshark -D", can also be used.
    ///
    /// If you're using UNIX, "netstat -i", "ifconfig -a" or "ip link" might also work to list interface names,
    /// although not all versions of UNIX support the -a option to ifconfig.
    /// Pipe names should be the name of a FIFO (named pipe).
    ///
    /// On Windows systems, pipe names must be of the form "\\pipe\.*pipename*".
    ///
    /// "TCP@\<host\>:\<port\>" causes TShark to attempt to connect to the specified port on the specified host and read pcapng or pcap data.
    ///
    /// Data read from pipes must be in standard pcapng or pcap format. Pcapng data must have the same endianness as the capturing host.
    ///
    /// ## Example: Prepare an instance of TShark to read from a fifo
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/my.fifo")
    ///     .live_capture();
    /// ```
    /// ## Example: Prepare an instance of TShark to read from a network interface
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("eth0")
    ///     .live_capture();
    /// ```

    pub fn input_path(&mut self, path: &'a str) -> RTSharkBuilderReady<'a> {
        RTSharkBuilderReady::<'a> {
            input_path: path,
            live_capture: false,
            metadata_blacklist: vec![],
            metadata_whitelist: None,
            capture_filter: "",
            display_filter: "",
            env_path: "",
            keylog_file: "",
            output_path: "",
            decode_as: vec![],
        }
    }
}

/// RTSharkBuilderReady is an object used to run to create a [RTShark] instance.
/// It is possible to use it to add more optional parameters before starting a TShark application.
#[derive(Clone)]
pub struct RTSharkBuilderReady<'a> {
    /// path to input source
    input_path: &'a str,
    /// activate live streaming (fifo, network interface). This activates -i option instread of -r.
    live_capture: bool,
    /// filter out (blacklist) useless metadata names, to prevent storing them in output packet structure
    metadata_blacklist: Vec<String>,
    /// filter out (whitelist) useless metadata names, to prevent TShark to put them in PDML report
    metadata_whitelist: Option<Vec<String>>,
    /// capture_filter : string to be passed to libpcap to filter packets (let pass only packets matching this filter)
    capture_filter: &'a str,
    /// display filter : expression filter to match before TShark prints a packet
    display_filter: &'a str,
    /// custom environment path containing TShark application
    env_path: &'a str,
    /// path to the key log file that enables decryption of TLS traffic
    keylog_file: &'a str,
    /// path to input source
    output_path: &'a str,
    /// decode_as : let TShark to decode as this expression
    decode_as: Vec<&'a str>,
}

impl<'a> RTSharkBuilderReady<'a> {
    /// Enables -i option of TShark.
    ///
    /// This option must be set to use network interface or pipe for live packet capture. See input_path() option of [RTSharkBuilder] for more details.
    ///
    pub fn live_capture(&self) -> Self {
        let mut new = self.clone();
        new.live_capture = true;
        new
    }

    /// Filter expression to be passed to libpcap to filter captured packets.
    ///
    /// Warning: these capture filters cannot be specified when reading a capture file.
    /// There are enabled only when using live_capture(). This filter will be ignored if live_capture() is not set.
    ///
    /// Packet capturing filter is performed with the pcap library.
    /// That library supports specifying a filter expression; packets that don't match that filter are discarded.
    /// The syntax of a capture filter is defined by the pcap library.
    /// This syntax is different from the TShark filter syntax.
    ///
    /// More information about libpcap filters here : <https://www.tcpdump.org/manpages/pcap-filter.7.html>
    ///
    /// ### Example: Prepare an instance of TShark with packet capture filter.
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("eth0")
    ///     .live_capture()
    ///     .capture_filter("port 53");
    /// ```
    pub fn capture_filter(&self, filter: &'a str) -> Self {
        let mut new = self.clone();
        new.capture_filter = filter;
        new
    }

    /// Expression applied on analyzed packet metadata to print and write only matching packets.
    ///
    /// Cause the specified filter (which uses the syntax of read/display filters, rather than that of capture filters)
    /// to be applied before printing a decoded form of packets or writing packets to a file.
    /// Packets matching the filter are printed or written to file; packets that the matching packets depend upon (e.g., fragments),
    /// are not printed but are written to file; packets not matching the filter nor depended upon are discarded rather than being printed or written.
    ///
    /// ### Example: Prepare an instance of TShark with display filter.
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/my.pcap")
    ///     .display_filter("udp.port == 53");
    /// ```
    pub fn display_filter(&self, filter: &'a str) -> Self {
        let mut new = self.clone();
        new.display_filter = filter;
        new
    }

    /// Filter out (blacklist) a list of useless metadata names extracted by TShark,
    /// to prevent storing them in [Packet] structure and consume extra memory.
    /// Filtered [Metadata] will not be available in [Packet]'s [Layer].
    ///
    /// This method can be called multiple times to add more metadata in the blacklist.
    ///
    /// ### Example: Prepare an instance of TShark with IP source and destination metadata filtered.
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/my.pcap")
    ///     .metadata_blacklist("ip.src")
    ///     .metadata_blacklist("ip.dst");
    /// ```
    pub fn metadata_blacklist(&self, blacklist: &'a str) -> Self {
        let mut new = self.clone();
        new.metadata_blacklist.push(blacklist.to_owned());
        new
    }

    /// Filter out (whitelist) a list of needed metadata names to be extracted by TShark,
    /// to prevent it to extract and put everything in the PDML report.
    /// There is a huge performance gain for TShark if the whitelist is small.
    /// Filtered [Metadata] will not be available in [Packet]'s [Layer].
    ///
    /// This method can be called multiple times to add more metadata in the whitelist.
    ///
    /// In whitelist mode, TShark PDML does not encapsulate fields in a <proto> tag anymore
    /// so it is not possible to build all packet's layers.
    ///
    /// ### Example: Prepare an instance of TShark to print only IP source and destination metadata.
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/my.pcap")
    ///     .metadata_whitelist("ip.src")
    ///     .metadata_whitelist("ip.dst");
    /// ```
    pub fn metadata_whitelist(&self, whitelist: &'a str) -> Self {
        let mut new = self.clone();
        if let Some(wl) = &mut new.metadata_whitelist {
            wl.push(whitelist.to_owned());
        } else {
            new.metadata_whitelist = Some(vec![whitelist.to_owned()]);
        }
        new
    }

    /// Replace the PATH environment variable. This is used to specify where to look for tshark executable.
    ///
    /// Note that environment variable names are case-insensitive (but case-preserving) on Windows,
    /// and case-sensitive on all other platforms.
    ///
    /// ### Example: Prepare an instance of TShark when binary is installed in a custom path
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/my.pcap")
    ///     .env_path("/opt/local/tshark/");
    /// ```
    pub fn env_path(&self, path: &'a str) -> Self {
        let mut new = self.clone();
        new.env_path = path;
        new
    }

    /// Specify the key log file that enables decryption of TLS traffic.
    ///
    /// The key log file is generated by the browser when `SSLKEYLOGFILE` environment variable
    /// is set. See <https://wiki.wireshark.org/TLS#using-the-pre-master-secret> for more
    /// details.
    ///
    /// Note that you can embed the TLS key log file in a capture file:
    ///
    /// ```no_compile
    /// editcap --inject-secrets tls,keys.txt in.pcap out-dsb.pcapng
    /// ```
    pub fn keylog_file(&self, path: &'a str) -> Self {
        let mut new = self.clone();
        new.keylog_file = path;
        new
    }

    /// Write raw packet data to outfile or to the standard output if outfile is '-'.
    /// Note : this option provides raw packet data, not text.
    ///
    /// ### Example: Prepare an instance of TShark to store raw packet data
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/in.pcap")
    ///     .output_path("/tmp/out.pcap");
    /// ```
    pub fn output_path(&self, path: &'a str) -> Self {
        let mut new = self.clone();
        new.output_path = path;
        new
    }

    /// Let TShark to decode as the protocol which specified in the expression.
    ///
    /// This method can be called multiple times to add more expression in the decode_as list.
    ///
    /// ### Example: The packet which has TCP port 8080 or 8081 is decoded as HTTP/2.
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/my.pcap")
    ///     .decode_as("tcp.port==8080,http2")
    ///     .decode_as("tcp.port==8081,http2");
    /// ```
    pub fn decode_as(&self, expr: &'a str) -> Self {
        let mut new = self.clone();
        new.decode_as.push(expr);
        new
    }

    /// Starts a new TShark process given the provided parameters, mapped to a new [RTShark] instance.
    /// This function may fail if tshark binary is not in PATH or if there are some issues with input_path parameter : not found or no read permission...
    /// In other cases (output_path not writable, invalid syntax for pcap_filter or display_filter),
    /// TShark process will start but will stop a few moments later, leading to a EOF on rtshark.read function.
    /// # Example
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/my.pcap");
    /// let tshark: std::io::Result<rtshark::RTShark> = builder.spawn();
    /// ```
    pub fn spawn(&self) -> Result<RTShark> {
        // test if input file exists
        if !self.live_capture {
            std::fs::metadata(self.input_path).map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => std::io::Error::new(
                    e.kind(),
                    format!("Unable to find {}: {}", &self.input_path, e),
                ),
                _ => e,
            })?;
        }

        // prepare tshark command line parameters
        let mut tshark_params = vec![
            if !self.live_capture { "-r" } else { "-i" },
            self.input_path,
            // Packet Details Markup Language, an XML-based format for the details of a decoded packet.
            // This information is equivalent to the packet details printed with the -V option.
            "-Tpdml",
            // Disable network object name resolution (such as hostname, TCP and UDP port names)
            "-n",
            // When capturing packets, TShark writes to the standard error an initial line listing the interfaces from which packets are being captured and,
            // if packet information isn’t being displayed to the terminal, writes a continuous count of packets captured to the standard output.
            // If the -Q option is specified, neither the initial line, nor the packet information, nor any packet counts will be displayed.
            "-Q",
        ];

        tshark_params.extend(&["-l"]);

        if !self.output_path.is_empty() {
            tshark_params.extend(&["-w", self.output_path]);
        }

        if self.live_capture && !self.capture_filter.is_empty() {
            tshark_params.extend(&["-f", self.capture_filter]);
        }

        if !self.display_filter.is_empty() {
            tshark_params.extend(&["-Y", self.display_filter]);
        }

        if !self.decode_as.is_empty() {
            for elm in self.decode_as.iter() {
                tshark_params.extend(&["-d", elm]);
            }
        }

        let opt_keylog = if self.keylog_file.is_empty() {
            None
        } else {
            Some(format!("tls.keylog_file:{}", self.keylog_file))
        };
        if let Some(ref keylog) = opt_keylog {
            tshark_params.extend(&["-o", keylog]);
        }
        if let Some(wl) = &self.metadata_whitelist {
            for whitelist_elem in wl {
                tshark_params.extend(&["-e", whitelist_elem]);
            }
        }

        // TODO: Greg added this
        //       Just use method metadata_whitelist // NOTE: this has bugs for "_ws.col.info"
        // tshark_params.extend(&["-e", "_ws.col.info"]);
        // Not compatible with PDML, will silently fail.
        // tshark_params.extend(&["-x"]); // add output of hex and ASCII dump (Packet Bytes)

        // piping from TShark, not to load the entire JSON in ram...
        // this may fail if TShark is not found in path

        println!("{:?}", tshark_params.join(" "));

        let tshark_child = if self.env_path.is_empty() {
            Command::new("tshark")
                .args(&tshark_params)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
        } else {
            Command::new("tshark")
                .args(&tshark_params)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .env("PATH", self.env_path)
                .spawn()
        };

        let mut tshark_child = tshark_child.map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                std::io::Error::new(e.kind(), format!("Unable to find tshark: {}", e))
            }
            _ => e,
        })?;

        let buf_reader = BufReader::new(tshark_child.stdout.take().unwrap());
        let stderr = BufReader::new(tshark_child.stderr.take().unwrap());

        let reader = quick_xml::Reader::from_reader(buf_reader);

        Ok(RTShark::new(
            tshark_child,
            reader,
            stderr,
            self.metadata_blacklist.clone(),
        ))
    }
}

/// RTShark structure represents a TShark process.
/// It allows controlling the TShark process and reading from application's output.
/// It is created by [RTSharkBuilder].
pub struct RTShark {
    /// Contains the TShark process handle, when TShark is running
    process: Option<Child>,
    /// xml parser on TShark piped output
    parser: quick_xml::Reader<BufReader<ChildStdout>>,
    /// stderr
    stderr: BufReader<ChildStderr>,
    /// optional metadata blacklist, to prevent storing useless metadata in output packet structure
    filters: Vec<String>,
}

impl RTShark {
    /// create a new RTShark instance from a successful builder call.
    fn new(
        process: Child,
        parser: quick_xml::Reader<BufReader<ChildStdout>>,
        stderr: BufReader<ChildStderr>,
        filters: Vec<String>,
    ) -> Self {
        RTShark {
            process: Some(process),
            parser,
            stderr,
            filters,
        }
    }

    /// Read a packet from thsark output and map it to the [Packet] type.
    /// Reading packet can be done until 'None' is returned.
    /// Once 'None' is returned, no more packets can be read from this stream
    /// and TShark instance can be dropped.
    /// This could happen when TShark application dies or when this is the end of the PCAP file.
    ///
    /// # Example
    ///
    /// ```
    /// # // Creates a builder with needed TShark parameters
    /// # let builder = rtshark::RTSharkBuilder::builder()
    /// #     .input_path("/tmp/my.pcap");
    /// // Start a new TShark process
    /// let mut rtshark = match builder.spawn() {
    ///     Err(err) => { eprintln!("Error running tshark: {err}"); return; }
    ///     Ok(rtshark) => rtshark
    /// };
    ///
    /// // read packets until the end of the PCAP file
    /// loop {
    ///     let packet = match rtshark.read() {
    ///         Ok(p) => p,
    ///         Err(e) => { eprintln!("Got decoding error: {e}"); continue; }
    ///     };
    ///
    ///     // end of stream
    ///     if let None = packet {
    ///         break;
    ///     }
    ///
    ///     println!("Got a packet");
    /// }
    /// ```
    pub fn read(&mut self) -> Result<Option<Packet>> {
        let xml_reader = &mut self.parser;

        let msg = parse_xml(xml_reader, &self.filters);
        if let Ok(ref msg) = msg {
            let done = match msg {
                None => {
                    // Got None == EOF
                    match self.process {
                        Some(ref mut process) => RTShark::try_wait_has_exited(process),
                        _ => true,
                    }
                }
                _ => false,
            };

            if done {
                self.process = None;

                // if process stops, there may be due to an error, we can get it in stderr
                let mut line = String::new();
                let size = self.stderr.read_line(&mut line)?;
                // if len is != 0 there is an error message
                if size != 0 {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, line));
                }
            }
        }

        msg
    }

    /// Kill the running TShark process associated to this rtshark instance.
    /// Once TShark is killed, there is no way to start it again using this object.
    /// Any new TShark instance has to be created using RTSharkBuilder.
    ///
    /// # Example
    ///
    /// ```
    /// // Creates a builder with needed TShark parameters
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/my.pcap");
    ///
    /// // Start a new TShark process
    /// let mut rtshark = match builder.spawn() {
    ///     Err(err) => { eprintln!("Error running tshark: {err}"); return; }
    ///     Ok(rtshark) => rtshark
    /// };
    ///
    /// // kill running TShark process
    /// rtshark.kill();
    /// ```

    pub fn kill(&mut self) {
        if let Some(ref mut process) = self.process {
            let done = match process.try_wait() {
                Ok(maybe) => match maybe {
                    None => false,
                    Some(_exitcode) => true,
                },
                Err(e) => {
                    eprintln!("Error while killing rtshark: wait: {e}");
                    false
                }
            };

            if !done {
                match process.kill() {
                    Ok(()) => (),
                    Err(e) => eprintln!("Error while killing rtshark: kill: {e}"),
                }
                if let Err(e) = process.wait() {
                    eprintln!("Error while killing rtshark: wait: {e}");
                }
            }

            self.process = None;
        }
    }

    /// Returns tshark process id if tshark is running.
    /// # Example
    ///
    /// ```
    /// // Creates a builder with needed tshark parameters
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/my.pcap");
    ///
    /// // Start a new tshark process
    /// let mut rtshark = match builder.spawn() {
    ///     Err(err) => { eprintln!("Error running tshark: {err}"); return; }
    ///     Ok(rtshark) => println!("tshark PID is {}", rtshark.pid().unwrap())
    /// };
    ///
    /// ```
    pub fn pid(&self) -> Option<u32> {
        self.process.as_ref().map(|p| p.id())
    }

    pub fn position(&self) -> usize {
        self.parser.buffer_position()
    }

    /// Check if process is stopped, get the exit code and return true if stopped.
    fn try_wait_has_exited(child: &mut Child) -> bool {
        #[cfg(target_family = "unix")]
        let value =
            matches!(child.try_wait(), Ok(Some(s)) if s.code().is_some() || s.signal().is_some());
        #[cfg(target_family = "windows")]
        let value = matches!(child.try_wait(), Ok(Some(s)) if s.code().is_some() );
        value
    }
}

impl Drop for RTShark {
    fn drop(&mut self) {
        self.kill()
    }
}

/// search for an attribute of a XML tag using its name and return a string.
fn rtshark_attr_by_name(tag: &BytesStart, key: &[u8]) -> Result<String> {
    let attrs = &mut tag.attributes();
    for attr in attrs {
        let attr = attr.map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Error decoding xml attribute: {e:?}"),
            )
        })?;
        if attr.key.as_ref() == key {
            let value = std::str::from_utf8(&attr.value).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Error decoding utf8 value: {e:?}"),
                )
            })?;
            return Ok(value.to_owned());
        }
    }

    let line =
        std::str::from_utf8(tag.attributes_raw()).unwrap_or("Unable to decode UTF8 XML buffer");

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "xml lookup error: no key '{}' in '{}'",
            std::str::from_utf8(key).unwrap(),
            line
        ),
    ))
}

/// search for an attribute of a XML tag using its name and return a u32.
fn rtshark_attr_by_name_u32(tag: &BytesStart, key: &[u8]) -> Result<u32> {
    match rtshark_attr_by_name(tag, key) {
        Err(e) => Err(e),
        Ok(v) => v.parse::<u32>().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Error decoding u32 value: {e:?}"),
            )
        }),
    }
}

/// Build a metadata using attributes available on this XML "field" tag.
/// Sample XML line : <field name="frame.time" show="test time" pos="0" size="0" showname="test time display"/>
fn rtshark_build_metadata(tag: &BytesStart, filters: &[String]) -> Result<Option<Metadata>> {
    let name = rtshark_attr_by_name(tag, b"name")?;

    // skip "_ws.expert" info, not related to a packet metadata
    if name.is_empty() || name.starts_with("_ws.") {
        return Ok(None);
    }

    // skip data
    if filters.contains(&name) {
        return Ok(None);
    }

    // Issue #1 : uses pyshark-like algorithm to display the best 'value' for this field
    // https://github.com/KimiNewt/pyshark/blob/master/src/pyshark/packet/fields.py#L14
    // try first "show", then "value", finally "showname"
    let value = match rtshark_attr_by_name(tag, b"show") {
        Ok(value) => Ok(value),
        Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
            match rtshark_attr_by_name(tag, b"value") {
                Ok(value) => Ok(value),
                Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
                    if let Ok(value) = rtshark_attr_by_name(tag, b"showname") {
                        Ok(value)
                    } else {
                        Err(err)
                    }
                }
                Err(err) => Err(err),
            }
        }
        Err(err) => Err(err),
    }?;

    // let raw_value = match rtshark_attr_by_name(tag, b"value") {
    //     Ok(value) => Ok(value),
    //     Err(err) => Err(err),
    // }?;
    let raw_value = rtshark_attr_by_name(tag, b"value").unwrap_or_default();
    let hide = match rtshark_attr_by_name(tag, b"hide")
        .unwrap_or_default()
        .as_str()
    {
        "yes" => true,
        _ => false,
    };

    let mut metadata = Metadata {
        name,
        value,
        raw_value,
        display: String::new(),
        size: 0,
        position: 0,
        hide,
    };

    if let Ok(position) = rtshark_attr_by_name_u32(tag, b"pos") {
        metadata.position = position;
    }
    if let Ok(size) = rtshark_attr_by_name_u32(tag, b"size") {
        metadata.size = size;
    }
    if let Ok(display) = rtshark_attr_by_name(tag, b"showname") {
        metadata.display = display;
    }
    Ok(Some(metadata))
}

/// Process specific metadata in geninfo to fill the packet structure
fn geninfo_metadata(tag: &BytesStart, packet: &mut Packet) -> Result<()> {
    use chrono::{LocalResult, TimeZone as _, Utc};

    let name = rtshark_attr_by_name(tag, b"name")?;
    if name != "timestamp" {
        return Ok(());
    }
    let value = rtshark_attr_by_name(tag, b"value")?;

    let bad_timestamp = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Error decoding timestamp: {value}"),
        )
    };

    let (secs, nsecs) = value.split_once('.').ok_or_else(bad_timestamp)?;
    let secs = secs.parse().map_err(|_| bad_timestamp())?;
    let nsecs = nsecs.parse().map_err(|_| bad_timestamp())?;

    let LocalResult::Single(dt) = Utc.timestamp_opt(secs, nsecs) else {
        return Err(bad_timestamp());
    };
    packet.timestamp_micros.replace(dt.timestamp_micros());

    Ok(())
}

/// list of protocols in tshark output but not in packet data
fn ignored_protocols(name: &str) -> bool {
    name.eq("geninfo") || name.eq("fake-field-wrapper")
}

/// Main parser function used to decode XML output from tshark
fn parse_xml<B: BufRead>(
    xml_reader: &mut quick_xml::Reader<B>,
    filters: &[String],
) -> Result<Option<Packet>> {
    let mut buf = vec![];
    let mut packet = Packet::new();

    let mut protoname = None;
    // let mut protonames: Vec<String> = Vec::new();

    // tshark pdml is something like : (default mode)
    //
    // <!-- You can find pdml2html.xsl in /usr/share/wireshark or at https://gitlab.com/wireshark/wireshark/-/raw/master/pdml2html.xsl. -->
    // <pdml version="0" creator="wireshark/4.0.6" time="Sat Oct  7 09:51:54 2023" capture_file="src/test.pcap">
    // <packet>
    //   <proto name="geninfo" pos="0" showname="General information" size="28">
    //     <field name="num" pos="0" show="1" showname="Number" value="1" size="28"/>
    //   </proto>
    //   <proto name="frame" pos="0" showname="General information" size="28">
    //   ...
    //
    // or, if using "whitelist" with -e option
    //
    // <pdml version="0" creator="wireshark/4.0.6" time="Sat Oct  7 09:51:54 2023" capture_file="src/test.pcap">
    // <packet>
    //   <proto name="geninfo" pos="0" showname="General information" size="28">
    //     <field name="num" pos="0" show="1" showname="Number" value="1" size="28"/>
    // </proto>
    // <field name="num" pos="0" show="1" showname="Number" value="1" size="28"/>
    // ...

    /// Create a new layer if required and add metadata to the given packet.
    fn _add_metadata(
        packet: &mut Packet,
        metadata: Metadata,
        size: usize,
        position: u32,
    ) -> Result<()> {
        // Create a new layer if the field's protocol does not exist yet as a layer.
        if let Some(proto) = metadata.name().split('.').next() {
            packet.push_if_not_exist(proto.to_owned(), size, position);
        }

        if let Some(layer) = packet.last_layer_mut() {
            layer.add(metadata);
        } else {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Cannot find protocol name to push a metadata",
            ));
        }

        Ok(())
    }

    fn _get_size(e: &BytesStart) -> usize {
        match rtshark_attr_by_name(e, b"size") {
            Ok(size) => size.parse().unwrap(),
            Err(_) => 0,
        }
    }

    fn _get_position(e: &BytesStart) -> u32 {
        match rtshark_attr_by_name(e, b"pos") {
            Ok(size) => size.parse().unwrap(),
            Err(_) => 0,
        }
    }

    loop {
        match xml_reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                // Here we have "packet" and "proto" and sometimes "field" tokens. Only "proto" and "field" are interesting today.
                // TODO: BUG! proto can be nested. Not sure how to handle this.
                /*if b"proto" == e.name().as_ref() && !protonames.is_empty() {
                    println!(
                        "Nested proto {:?} found in {:?}",
                        rtshark_attr_by_name(e, b"name"),
                        protonames.last()
                    );
                    let proto = rtshark_attr_by_name(e, b"name")?;
                    protonames.push(proto.to_owned());
                } else */
                if b"proto" == e.name().as_ref() {
                    let proto = rtshark_attr_by_name(e, b"name")?;
                    protoname = Some(proto.to_owned());
                    // println!("new proto started {:?}", proto);
                    // protonames.push(proto.to_owned());

                    // let size: usize = match rtshark_attr_by_name(e, b"size"){
                    //     Ok(size) => size.parse().unwrap(),
                    //     Err(_) => 0,
                    // };

                    // // packet.size = size;

                    // If we face a new protocol, add it in the packet layers stack.
                    if !ignored_protocols(proto.as_str()) {
                        packet.push(proto, _get_size(e), _get_position(e));
                    }
                }
                // There are cases where fields are mapped in fields. So check if there is any parent field and extract its metadata.
                else if b"field" == e.name().as_ref() {
                    // println!("new field {:?} started for proto {:?}", e, protonames.last());
                    if let Some(metadata) = rtshark_build_metadata(e, filters)? {
                        // println!("new metadata {:?}", metadata.name);
                        _add_metadata(&mut packet, metadata, _get_size(e), _get_position(e))?;
                    }
                }
            }
            Ok(Event::Empty(ref e)) => {
                // Handle the case of empty, i.e. self-closing, tags. For example:
                //      <field name="field.name" ... />
                // Here we should not have anything else than "field" but do a test anyway.
                // debug_assert_eq!(b"field", e.name().as_ref(), "{:?}", e);
                if b"field" == e.name().as_ref() {
                    // let last_layer_name = if packet.last_layer_mut().is_some() {
                    //     packet.last_layer_mut().unwrap().name().to_owned()
                    // } else {
                    //     String::new()
                    // };
                    // println!("{:?}    last layer =  {:?}", e, last_layer_name);
                    // Here we have two cases : with or without encapsuling "proto"
                    // We have a protocol if "whitelist" mode is disabled.
                    // Protocol "geninfo" is always here.
                    // if let Some(name) = protonames.last().as_ref() {
                    if let Some(name) = protoname.as_ref() {
                        if ignored_protocols(name) {
                            // Put geninfo metadata in packet's object (timestamp ...).
                            geninfo_metadata(e, &mut packet)?;
                        } else if let Some(metadata) = rtshark_build_metadata(e, filters)? {
                            // We can unwrap because we must have a layer : it was pushed in Event::Start
                            packet.last_layer_mut().unwrap().add(metadata);
                        }
                    } else if let Some(metadata) = rtshark_build_metadata(e, filters)? {
                        _add_metadata(&mut packet, metadata, _get_size(e), _get_position(e))?;
                    }
                }
            }
            Ok(Event::End(ref e)) => match e.name().as_ref() {
                b"packet" => return Ok(Some(packet)),
                b"proto" => {
                    // println!("{:?}", e.name());
                    // let proto = rtshark_attr_by_name(e, b"name")?;
                    // if proto != protoname.unwrap_or("".into()) {
                    //     println!("END proto end {:?} does not equal existing proto {:?}", proto, protoname);
                    // }
                    // protonames.pop();
                    protoname = None
                }
                _ => (),
            },

            Ok(Event::Eof) => {
                return Ok(None);
            }
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "xml parsing error: {} at tshark output offset {}",
                        e,
                        xml_reader.buffer_position()
                    ),
                ));
            }
            Ok(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {

    use std::io::Write;

    use serial_test::serial;

    use super::*;

    #[test]
    fn test_parse_single_proto_metadata() {
        let xml = r#"
        <pdml>
         <packet>
          <proto name="frame">
           <field name="frame.time" show="test time" pos="0" size="0" showname="test time display"/>
          </proto>
         </packet>
        </pdml>"#;

        let mut reader = quick_xml::Reader::from_reader(BufReader::new(xml.as_bytes()));

        let msg = parse_xml(&mut reader, &[]).unwrap();
        let pkt = match msg {
            Some(p) => p,
            _ => panic!("invalid Output type"),
        };

        assert_eq!(pkt.layers.len(), 1);
        for layer in pkt.layers {
            for m in layer {
                assert!(m.name().eq("frame.time"));
                assert!(m.value().eq("test time"));
                assert!(m.display().eq("test time display"));
            }
        }
    }

    #[test]
    fn test_parse_missing_optional_size() {
        let xml = r#"
        <pdml>
         <packet>
          <proto name="frame">
          <field name="frame.time" show="test time" pos="0" showname="test time display"/>
          </proto>
         </packet>
        </pdml>"#;

        let mut reader = quick_xml::Reader::from_reader(BufReader::new(xml.as_bytes()));

        let msg = parse_xml(&mut reader, &[]).unwrap();
        let pkt = match msg {
            Some(p) => p,
            _ => panic!("invalid Output type"),
        };

        assert_eq!(pkt.layers.len(), 1);
    }

    #[test]
    fn test_parse_missing_optional_pos() {
        let xml = r#"
        <pdml>
         <packet>
          <proto name="frame">
          <field name="frame.time" show="test time" size="0" showname="test time display"/>
          </proto>
         </packet>
        </pdml>"#;

        let mut reader = quick_xml::Reader::from_reader(BufReader::new(xml.as_bytes()));

        let msg = parse_xml(&mut reader, &[]).unwrap();
        let pkt = match msg {
            Some(p) => p,
            _ => panic!("invalid Output type"),
        };

        assert_eq!(pkt.layers.len(), 1);
    }

    #[test]
    fn test_parse_missing_optional_display() {
        let xml = r#"
        <pdml>
         <packet>
          <proto name="frame">
          <field name="frame.time" show="test time" pos="0" size="0" />
          </proto>
         </packet>
        </pdml>"#;

        let mut reader = quick_xml::Reader::from_reader(BufReader::new(xml.as_bytes()));

        let msg = parse_xml(&mut reader, &[]).unwrap();
        let pkt = match msg {
            Some(p) => p,
            _ => panic!("invalid Output type"),
        };

        assert_eq!(pkt.layers.len(), 1);
    }

    #[test]
    fn test_parse_missing_mandatory_name() {
        let xml = r#"
        <pdml>
         <packet>
          <proto name="frame">
          <field show="test time" pos="0" size="0" showname="test time display"/>
          </proto>
         </packet>
        </pdml>"#;

        let mut reader = quick_xml::Reader::from_reader(BufReader::new(xml.as_bytes()));

        let msg = parse_xml(&mut reader, &[]);

        match msg {
            Err(_) => (),
            _ => panic!("invalid result"),
        }
    }

    #[test]
    fn test_parse_missing_show_attribute() {
        // Issue #1 : uses pyshark-like algorithm to display the best 'value' for this field
        // https://github.com/KimiNewt/pyshark/blob/master/src/pyshark/packet/fields.py#L14
        // try first "show", then "value", finally "showname"

        let xml = r#"
        <pdml>
         <packet>
          <proto name="icmp">
           <field name="data" value="0a" showname="data: a0"/>
          </proto>
         </packet>
        </pdml>"#;

        let mut reader = quick_xml::Reader::from_reader(BufReader::new(xml.as_bytes()));

        let pkt = parse_xml(&mut reader, &[]).unwrap().unwrap();

        let icmp = pkt.layer_name("icmp").unwrap();
        let data = icmp.metadata("data").unwrap();
        assert!(data.value().eq("0a"));
    }

    #[test]
    fn test_parse_missing_show_and_value_attributes() {
        // Issue #1 : uses pyshark-like algorithm to display the best 'value' for this field
        // https://github.com/KimiNewt/pyshark/blob/master/src/pyshark/packet/fields.py#L14
        // try first "show", then "value", finally "showname"

        let xml = r#"
        <pdml>
         <packet>
          <proto name="icmp">
           <field name="data" showname="data: a0"/>
          </proto>
         </packet>
        </pdml>"#;

        let mut reader = quick_xml::Reader::from_reader(BufReader::new(xml.as_bytes()));

        let pkt = parse_xml(&mut reader, &[]).unwrap().unwrap();

        let icmp = pkt.layer_name("icmp").unwrap();
        let data = icmp.metadata("data").unwrap();
        assert!(data.value().eq("data: a0"));
    }

    #[test]
    fn test_parse_missing_any_show() {
        let xml = r#"
        <pdml>
         <packet>
          <proto name="frame">
          <field name="frame.time" pos="0" size="0"/>
          </proto>
         </packet>
        </pdml>"#;

        let mut reader = quick_xml::Reader::from_reader(BufReader::new(xml.as_bytes()));

        let msg = parse_xml(&mut reader, &[]);
        match msg {
            Err(_) => (),
            _ => panic!("invalid result"),
        }
    }

    const XML_TCP: &str = r#"
    <pdml>
     <packet>
      <proto name="frame">
       <field name="frame.time" show="Mar  5, 2021 08:49:52.736275000 CET"/>
      </proto>
      <proto name="ip">
       <field name="ip.src" show="1.1.1.1" />
       <field name="ip.dst" show="1.1.1.2" />
      </proto>
      <proto name="tcp">
       <field name="tcp.srcport" show="52796" value="ce3c"/>
       <field name="tcp.dstport" show="5432" value="1538"/>
       <field name="tcp.seq_raw" show="1963007432" value="75011dc8"/>
       <field name="tcp.stream" show="4"/>
      </proto>
     </packet>
    </pdml>"#;

    #[test]
    fn test_access_packet_into_iter() {
        let mut reader = quick_xml::Reader::from_reader(BufReader::new(XML_TCP.as_bytes()));

        let msg = parse_xml(&mut reader, &[]).unwrap();
        let pkt = match msg {
            Some(p) => p,
            _ => panic!("invalid Output type"),
        };

        assert_eq!(pkt.layers.len(), 3);

        let mut iter = pkt.into_iter();
        let frame = iter.next().unwrap();
        assert!(frame.name().eq("frame"));
        let ip = iter.next().unwrap();
        assert!(ip.name().eq("ip"));
        let tcp = iter.next().unwrap();
        assert!(tcp.name().eq("tcp"));
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_access_packet_iter() {
        let mut reader = quick_xml::Reader::from_reader(BufReader::new(XML_TCP.as_bytes()));

        let msg = parse_xml(&mut reader, &[]).unwrap();
        let pkt = match msg {
            Some(p) => p,
            _ => panic!("invalid Output type"),
        };

        assert_eq!(pkt.layers.len(), 3);

        let mut iter = pkt.iter();
        let frame = iter.next().unwrap();
        assert!(frame.name().eq("frame"));
        let ip = iter.next().unwrap();
        assert!(ip.name().eq("ip"));
        let tcp = iter.next().unwrap();
        assert!(tcp.name().eq("tcp"));
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_access_layer_index() {
        let mut reader = quick_xml::Reader::from_reader(BufReader::new(XML_TCP.as_bytes()));

        let msg = parse_xml(&mut reader, &[]).unwrap();
        let pkt = match msg {
            Some(p) => p,
            _ => panic!("invalid Output type"),
        };

        assert_eq!(pkt.layers.len(), 3);

        assert!(pkt.layer_index(0).unwrap().name().eq("frame"));
        assert!(pkt.layer_index(1).unwrap().name().eq("ip"));
        assert!(pkt.layer_index(2).unwrap().name().eq("tcp"));

        assert!(pkt.layer_index(3).is_none());
    }

    #[test]
    fn test_access_layer_name() {
        let mut reader = quick_xml::Reader::from_reader(BufReader::new(XML_TCP.as_bytes()));

        let msg = parse_xml(&mut reader, &[]).unwrap();
        let pkt = match msg {
            Some(p) => p,
            _ => panic!("invalid Output type"),
        };

        assert_eq!(pkt.layers.len(), 3);

        assert!(pkt.layer_name("frame").unwrap().name().eq("frame"));
        assert!(pkt.layer_name("ip").unwrap().name().eq("ip"));
        assert!(pkt.layer_name("tcp").unwrap().name().eq("tcp"));

        assert!(pkt.layer_name("udp").is_none());
    }

    #[test]
    fn test_access_layer_name_with_tunnel() {
        let xml = r#"
        <pdml>
         <packet>
          <proto name="frame">
           <field name="frame.time" show="Mar  5, 2021 08:49:52.736275000 CET"/>
          </proto>
          <proto name="ip">
           <field name="ip.src" show="10.215.215.9" />
           <field name="ip.dst" show="10.215.215.10" />
          </proto>
          <proto name="ip">
           <field name="ip.src" show="10.10.215.9" />
           <field name="ip.dst" show="10.10.215.10" />
          </proto>
          <proto name="tcp">
           <field name="tcp.srcport" show="52796" value="ce3c"/>
           <field name="tcp.dstport" show="5432" value="1538"/>
           <field name="tcp.seq_raw" show="1963007432" value="75011dc8"/>
           <field name="tcp.stream" show="4"/>
          </proto>
         </packet>
        </pdml>"#;

        let mut reader = quick_xml::Reader::from_reader(BufReader::new(xml.as_bytes()));

        let msg = parse_xml(&mut reader, &[]).unwrap();
        let pkt = match msg {
            Some(p) => p,
            _ => panic!("invalid Output type"),
        };

        assert_eq!(pkt.layers.len(), 4);

        assert!(pkt.layer_name("frame").unwrap().name().eq("frame"));
        assert!(pkt.layer_name("ip").unwrap().name().eq("ip"));
        assert!(pkt.layer_name("ip").unwrap().index() == 1usize);
        assert!(pkt.layer_index(1).unwrap().name().eq("ip"));
        assert!(pkt.layer_index(2).unwrap().name().eq("ip"));
        assert!(pkt.layer_name("tcp").unwrap().name().eq("tcp"));

        assert!(pkt.layer_name("udp").is_none());
    }

    #[test]
    fn test_access_layer_iter() {
        let mut reader = quick_xml::Reader::from_reader(BufReader::new(XML_TCP.as_bytes()));

        let msg = parse_xml(&mut reader, &[]).unwrap();
        let pkt = match msg {
            Some(p) => p,
            _ => panic!("invalid Output type"),
        };

        let ip = pkt.layer_name("ip").unwrap();
        let mut iter = ip.iter();
        assert!(iter.next().unwrap().name().eq("ip.src"));
        assert!(iter.next().unwrap().name().eq("ip.dst"));
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_access_layer_into_iter() {
        let mut reader = quick_xml::Reader::from_reader(BufReader::new(XML_TCP.as_bytes()));

        let msg = parse_xml(&mut reader, &[]).unwrap();
        let pkt = match msg {
            Some(p) => p,
            _ => panic!("invalid Output type"),
        };

        let ip = pkt.layer_name("ip").unwrap().clone();
        let mut iter = ip.into_iter();
        assert!(iter.next().unwrap().name().eq("ip.src"));
        assert!(iter.next().unwrap().name().eq("ip.dst"));
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_access_layer_metadata() {
        let mut reader = quick_xml::Reader::from_reader(BufReader::new(XML_TCP.as_bytes()));

        let msg = parse_xml(&mut reader, &[]).unwrap();
        let pkt = match msg {
            Some(p) => p,
            _ => panic!("invalid Output type"),
        };

        let ip = pkt.layer_name("ip").unwrap();
        let src = ip.metadata("ip.src").unwrap();
        assert!(src.value().eq("1.1.1.1"));

        let dst = ip.metadata("ip.dst").unwrap();
        assert!(dst.value().eq("1.1.1.2"));
    }

    #[test]
    fn test_parser_filter_metadata() {
        let mut reader = quick_xml::Reader::from_reader(BufReader::new(XML_TCP.as_bytes()));

        let msg = parse_xml(&mut reader, &["ip.src".to_string()]).unwrap();
        let pkt = match msg {
            Some(p) => p,
            _ => panic!("invalid Output type"),
        };

        let ip = pkt.layer_name("ip").unwrap();
        assert!(ip.metadata("ip.src").is_none());
        assert!(ip.metadata("ip.dst").unwrap().value().eq("1.1.1.2"));
    }

    #[test]
    fn test_parser_multiple_packets() {
        let xml = r#"
        <pdml>
         <packet>
          <proto name="tcp"></proto>
         </packet>
         <packet>
          <proto name="udp"></proto>
         </packet>
         <packet>
          <proto name="igmp"></proto>
         </packet>
        </pdml>"#;

        let mut reader = quick_xml::Reader::from_reader(BufReader::new(xml.as_bytes()));
        match parse_xml(&mut reader, &[]).unwrap() {
            Some(p) => assert!(p.layer_name("tcp").is_some()),
            _ => panic!("invalid Output type"),
        }
        match parse_xml(&mut reader, &[]).unwrap() {
            Some(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }
        match parse_xml(&mut reader, &[]).unwrap() {
            Some(p) => assert!(p.layer_name("igmp").is_some()),
            _ => panic!("invalid Output type"),
        }
        match parse_xml(&mut reader, &[]).unwrap() {
            None => (),
            _ => panic!("invalid Output type"),
        }
    }

    #[test]
    fn test_rtshark_field_in_field() {
        let xml = r#"
        <pdml>
         <packet>
          <proto name="btcommon">
            <field name="btcommon.eir_ad.entry.data" showname="Data: <data>" size="8" pos="39" show="<some data>" value="<some data>">
              <field name="_ws.expert" showname="Expert Info (Note/Undecoded): Undecoded" size="0" pos="39">
                <field name="btcommon.eir_ad.undecoded" showname="Undecoded" size="0" pos="0" show="" value=""/>
                <field name="_ws.expert.message" showname="Message: Undecoded" hide="yes" size="0" pos="0" show="Undecoded"/>
                <field name="_ws.expert.severity" showname="Severity level: Note" size="0" pos="0" show="4194304"/>
                <field name="_ws.expert.group" showname="Group: Undecoded" size="0" pos="0" show="83886080"/>
              </field>
            </field>
          </proto>
         </packet>
        </pdml>"#;

        let mut reader = quick_xml::Reader::from_reader(BufReader::new(xml.as_bytes()));
        match parse_xml(&mut reader, &[]).unwrap() {
            Some(p) => match p.layer_name("btcommon") {
                Some(layer) => {
                    layer
                        .metadata("btcommon.eir_ad.entry.data")
                        .unwrap_or_else(|| panic!("Missing btcommon.eir_ad.entry.data"));

                    layer
                        .metadata("btcommon.eir_ad.undecoded")
                        .unwrap_or_else(|| panic!("Missing btcommon.eir_ad.undecoded"));
                }
                None => panic!("missing protocol"),
            },
            _ => panic!("invalid Output type"),
        }
    }

    #[test]
    fn test_parse_xml_proto_in_proto() {
        let xml = r#"
        <pdml>
         <packet>
        <proto name="icmp" showname="Internet Control Message Protocol" size="36" pos="34">
            <field name="icmp.type" showname="Type: 3 (Destination unreachable)" size="1" pos="34" show="3" value="03"/>
            <field name="icmp.code" showname="Code: 3 (Port unreachable)" size="1" pos="35" show="3" value="03"/>
            <field name="icmp.checksum" showname="Checksum: 0xfe7b [correct]" size="2" pos="36" show="0xfe7b" value="fe7b"/>
            <field name="icmp.checksum.status" showname="Checksum Status: Good" size="0" pos="36" show="1"/>
            <field name="icmp.unused" showname="Unused: 00000000" size="4" pos="38" show="00:00:00:00" value="00000000"/>
            <proto name="ip" showname="Internet Protocol Version 4, Src: xxx.xxx.xxx.xxx, Dst: 192.168.2.44" size="20" pos="42">
                <field name="ip.version" showname="0100 .... = Version: 4" size="1" pos="42" show="4" value="45"/>
                <field name="ip.hdr_len" showname=".... 0101 = Header Length: 20 bytes (5)" size="1" pos="42" show="20" value="45"/>
                <field name="ip.dsfield" showname="Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)" size="1" pos="43" show="0x00" value="00">
                    <field name="ip.dsfield.dscp" showname="0000 00.. = Differentiated Services Codepoint: Default (0)" size="1" pos="43" show="0" value="0" unmaskedvalue="00"/>
                    <field name="ip.dsfield.ecn" showname=".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)" size="1" pos="43" show="0" value="0" unmaskedvalue="00"/>
                </field>
                <field name="ip.len" showname="Total Length: 59" size="2" pos="44" show="59" value="003b"/>
                <field name="ip.id" showname="Identification: 0x0000 (0)" size="2" pos="46" show="0x0000" value="0000"/>
                <field name="ip.flags" showname="010. .... = Flags: 0x2, Don&#x27;t fragment" size="1" pos="48" show="0x02" value="2" unmaskedvalue="40">
                    <field name="ip.flags.rb" showname="0... .... = Reserved bit: Not set" size="1" pos="48" show="False" value="0" unmaskedvalue="40"/>
                    <field name="ip.flags.df" showname=".1.. .... = Don&#x27;t fragment: Set" size="1" pos="48" show="True" value="1" unmaskedvalue="40"/>
                    <field name="ip.flags.mf" showname="..0. .... = More fragments: Not set" size="1" pos="48" show="False" value="0" unmaskedvalue="40"/>
                </field>
                <field name="ip.frag_offset" showname="...0 0000 0000 0000 = Fragment Offset: 0" size="2" pos="48" show="0" value="0" unmaskedvalue="4000"/>
                <field name="ip.ttl" showname="Time to Live: 58" size="1" pos="50" show="58" value="3a"/>
                <field name="ip.proto" showname="Protocol: UDP (17)" size="1" pos="51" show="17" value="11"/>
                <field name="ip.checksum" showname="Header Checksum: 0xcb34 [validation disabled]" size="2" pos="52" show="0xcb34" value="cb34"/>
                <field name="ip.checksum.status" showname="Header checksum status: Unverified" size="0" pos="52" show="2"/>
                <field name="ip.src" showname="Source Address: xxx.xxx.xxx.xxx" size="4" pos="54" show="xxx.xxx.xxx.xxx" value="8efb23ae"/>
                <field name="ip.addr" showname="Source or Destination Address: xxx.xxx.xxx.xxx" hide="yes" size="4" pos="54" show="xxx.xxx.xxx.xxx" value="8efb23ae"/>
                <field name="ip.src_host" showname="Source Host: xxx.xxx.xxx.xxx" hide="yes" size="4" pos="54" show="xxx.xxx.xxx.xxx" value="8efb23ae"/>
                <field name="ip.host" showname="Source or Destination Host: xxx.xxx.xxx.xxx" hide="yes" size="4" pos="54" show="xxx.xxx.xxx.xxx" value="8efb23ae"/>
                <field name="ip.dst" showname="Destination Address: 192.168.2.44" size="4" pos="58" show="192.168.2.44" value="c0a8022c"/>
                <field name="ip.addr" showname="Source or Destination Address: 192.168.2.44" hide="yes" size="4" pos="58" show="192.168.2.44" value="c0a8022c"/>
                <field name="ip.dst_host" showname="Destination Host: 192.168.2.44" hide="yes" size="4" pos="58" show="192.168.2.44" value="c0a8022c"/>
                <field name="ip.host" showname="Source or Destination Host: 192.168.2.44" hide="yes" size="4" pos="58" show="192.168.2.44" value="c0a8022c"/>
            </proto>
            <proto name="udp" showname="User Datagram Protocol, Src Port: 443, Dst Port: 64670" size="8" pos="62">
                <field name="udp.srcport" showname="Source Port: 443" size="2" pos="62" show="443" value="01bb"/>
                <field name="udp.dstport" showname="Destination Port: 64670" size="2" pos="64" show="64670" value="fc9e"/>
                <field name="udp.port" showname="Source or Destination Port: 443" hide="yes" size="2" pos="62" show="443" value="01bb"/>
                <field name="udp.port" showname="Source or Destination Port: 64670" hide="yes" size="2" pos="64" show="64670" value="fc9e"/>
                <field name="udp.length" showname="Length: 39" size="2" pos="66" show="39" value="0027"/>
                <field name="udp.checksum" showname="Checksum: 0x0000 [zero-value ignored]" size="2" pos="68" show="0x0000" value="0000">
                    <field name="udp.checksum.status" showname="Checksum Status: Not present" size="2" pos="68" show="3" value="0000"/>
                </field>
                <field name="udp.stream" showname="Stream index: 11" size="0" pos="70" show="11"/>
            </proto>
        </proto>
         </packet>
        </pdml>"#;

        let mut reader = quick_xml::Reader::from_reader(BufReader::new(xml.as_bytes()));
        match parse_xml(&mut reader, &[]).unwrap() {
            Some(p) => match p.layer_name("icmp") {
                Some(layer) => {
                    let metadata_name = "icmp.type";
                    layer
                        .metadata(metadata_name)
                        .unwrap_or_else(|| panic!("Missing {}", metadata_name));

                    let metadata_name = "ip.version";
                    layer
                        .metadata(metadata_name)
                        .unwrap_or_else(|| panic!("Missing {}", metadata_name));
                }
                None => panic!("missing protocol"),
            },
            _ => panic!("invalid Output type"),
        }

        let xml = r#"
        <pdml>
         <packet>
        <proto name="quic" showname="QUIC IETF" size="1250" pos="42">
    <field name="" show="QUIC Connection information" size="0" pos="42">
      <field name="quic.connection.number" showname="Connection Number: 10" size="0" pos="42" show="10"/>
    </field>
    <field name="quic.packet_length" showname="Packet Length: 1250" size="0" pos="42" show="1250"/>
    <field name="quic.header_form" showname="1... .... = Header Form: Long Header (1)" size="1" pos="42" show="1" value="1" unmaskedvalue="c9"/>
    <field name="quic.fixed_bit" showname=".1.. .... = Fixed Bit: True" size="1" pos="42" show="True" value="1" unmaskedvalue="c9"/>
    <field name="quic.long.packet_type" showname="..00 .... = Packet Type: Initial (0)" size="1" pos="42" show="0" value="0" unmaskedvalue="c9"/>
    <field name="quic.long.reserved" showname=".... 00.. = Reserved: 0" size="1" pos="42" show="0" value="0" unmaskedvalue="c9"/>
    <field name="quic.packet_number_length" showname=".... ..00 = Packet Number Length: 1 bytes (0)" size="1" pos="42" show="0" value="0" unmaskedvalue="c9"/>
    <field name="quic.version" showname="Version: 1 (0x00000001)" size="4" pos="43" show="0x00000001" value="00000001"/>
    <field name="quic.dcil" showname="Destination Connection ID Length: 0" size="1" pos="47" show="0" value="00"/>
    <field name="quic.scil" showname="Source Connection ID Length: 8" size="1" pos="48" show="8" value="08"/>
    <field name="quic.scid" showname="Source Connection ID: f15dc23d0d5fb6c2" size="8" pos="49" show="f1:5d:c2:3d:0d:5f:b6:c2" value="f15dc23d0d5fb6c2"/>
    <field name="quic.token_length" showname="Token Length: 0" size="1" pos="57" show="0" value="00"/>
    <field name="quic.length" showname="Length: 1232" size="2" pos="58" show="1232" value="44d0"/>
    <field name="quic.packet_number" showname="Packet Number: 1" size="1" pos="60" show="1" value="91"/>
    <field name="quic.payload" showname="Payload [truncated]: 497afa0c28063859143976f2c610146c21ad0c87b08b8385d69b1ad1dd4e6f71163aafdb3e59f8419f73ffd3013cbe25cc57b48db2502253adb6afbb6af97fef683519ebce14843948f5d8a92a4fdd8e33144b5247ba94db90e380d68219bfdb73d979d2827486eec1d48b5662" size="1231" pos="61" show="49:7a:fa:0c:28:06:38:59:14:39:76:f2:c6:10:14:6c:21:ad:0c:87:b0:8b:83:85:d6:9b:1a:d1:dd:4e:6f:71:16:3a:af:db:3e:59:f8:41:9f:73:ff:d3:01:3c:be:25:cc:57:b4:8d:b2:50:22:53:ad:b6:af:bb:6a:f9:7f:ef:68:35:19:eb:ce:14:84:39:48:f5:d8:a9:2a:4f:dd:8e:33:14:4b:52:47:ba:94:db:90:e3:80:d6:82:19:bf:db:73:d9:79:d2:82:74:86:ee:c1:d4:8b:56:62:37:9b:4f:e7:03:10:78:14:05:c7:71:1e:08:e9:5b:43:73:27:9d:ea:b8:c9:6a:4d:9e:be:74:bd:4e:4d:0a:b7:03:f1:1f:04:62:a3:2c:f1:5d:0e:27:c0:5d:25:d0:01:ce:f2:f6:2c:92:47:e6:fb:ab:6d:5e:bd:ad:5b:a1:f5:da:a3:60:70:0d:5a:98:a4:09:4f:94:61:59:68:aa:d5:01:b5:00:23:ff:22:bc:1b:d0:5f:36:ea:db:4c:91:80:f6:2b:43:8d:4b:1b:ae:c7:dd:14:a3:5f:f5:4d:8f:b0:0e:88:1c:d2:ba:2e:e9:ef:82:64:cb:b9:d9:fb:1c:7c:2b:77:ee:18:1a:26:5b:0c:28:db:77:8a:84:97:bb:3d:ef:51:bf:00:49:57:63:bb:58:aa:38:46:ea:f2:ef:00:c7:91:50:ff:7f:36:b0:58:55:c9:b4:a8:2f:2e:33:8b:bc:d7:dc:d5:6a:69:59:e2:ee:ec:85:42:20:8c:76:2c:3f:a2:dc:07:db:13:95:48:12:a7:ea:7f:de:fa:14:bd:34:5b:13:ab:51:cb:97:62:77:c8:73:69:f1:8e:ec:f5:0f:16:ce:88:da:b1:20:07:3a:8b:8f:5b:30:21:ef:60:4b:d4:66:d7:f1:a4:21:8c:93:de:87:90:78:90:34:9c:0c:02:7a:14:8f:47:81:ee:78:03:be:05:00:b4:bc:6f:e1:17:6e:56:c0:85:95:b4:1d:8a:05:48:cb:0d:20:dc:80:08:2c:19:96:44:01:2f:26:eb:d4:c5:6d:59:06:eb:14:fb:71:f0:66:f3:3e:4f:a2:c8:48:14:14:fb:77:27:bd:f4:73:31:11:69:39:a7:c2:38:64:b5:ca:82:ba:95:3a:fe:71:f1:a1:03:64:b8:46:c5:e1:89:de:be:44:da:7d:e1:aa:c7:c0:1d:1e:28:48:0f:12:2e:f8:67:48:6a:f1:a5:1a:20:9b:42:47:ed:7c:e9:6e:84:85:81:70:58:fd:5f:64:7a:b6:99:95:1f:60:9d:72:5a:b0:e0:da:6a:3b:ce:12:58:b9:ba:62:0b:e4:14:f2:f5:61:ff:3d:f5:c0:41:b2:53:93:c9:96:a9:23:3b:fc:3f:a6:39:40:6e:db:e7:28:74:8e:25:f9:bc:4a:14:b7:f5:36:1b:fd:e4:ef:3a:49:0b:4e:86:22:30:e8:49:d1:98:a6:d8:d7:f1:91:21:f0:b5:10:23:f5:e7:4a:d5:1f:e8:9f:f9:37:52:51:75:c6:73:fb:8f:44:1f:a2:82:66:17:3f:f4:0c:fb:ee:eb:f9:06:7d:59:0b:82:35:ac:f2:55:0d:49:ab:c7:0e:02:ee:43:f6:b4:7c:01:f4:11:66:75:b4:75:a3:bd:2e:0b:de:88:80:37:8d:bb:6a:95:2e:1e:b1:2d:e6:ac:00:a7:9c:ff:53:cf:62:53:94:6c:24:3b:2c:af:3e:e9:5d:59:9a:47:71:10:b2:83:1e:97:c1:82:62:9f:22:8a:d9:b5:37:62:10:fa:80:ab:af:4f:39:d1:9f:0e:c3:50:b6:99:f6:4d:28:33:fb:08:c9:d0:cd:ce:1d:ea:3a:18:05:a1:6c:0e:18:c9:fd:f0:3e:6e:8d:53:ee:a5:82:bf:30:ca:98:ec:f8:3a:22:52:f3:39:59:df:4d:1d:3d:08:0f:a6:f1:d3:f5:b2:1b:e1:68:23:bd:01:c3:b1:64:da:af:53:f8:2b:6d:f9:96:83:b2:49:89:5d:d4:ea:e5:c4:72:fc:b3:10:dd:b4:30:55:06:3c:0c:59:96:86:1b:c4:75:04:f6:28:6a:15:a4:02:c7:17:9d:10:0e:1c:f0:ad:67:ee:af:fb:06:41:7b:0b:f9:62:9e:c8:86:df:93:a6:54:8c:49:92:e0:eb:81:d0:f7:7c:ae:c5:2a:7d:e1:c9:f9:43:35:7d:b5:8a:0e:1f:fb:e3:5a:9a:71:0e:52:94:da:72:e4:bc:3f:be:e5:91:61:ce:f4:01:96:9a:8e:25:f3:68:56:28:1d:13:40:ba:28:f4:cd:44:f9:28:16:a4:90:b1:22:19:e4:6b:e6:9b:24:7b:7d:e5:d7:a9:e6:c6:27:33:7c:8e:a0:a8:27:a5:06:d7:00:8a:3a:0b:28:04:f0:61:39:77:84:3e:cb:21:fc:ae:3d:9f:eb:ad:ee:f4:8d:28:a2:0c:55:94:05:57:ba:79:bd:1f:77:f6:7e:5c:46:31:c2:8a:25:52:81:82:1f:65:66:61:dc:32:d9:bc:5d:8a:a3:ae:f9:63:8e:91:17:5a:c6:8d:fc:56:50:ab:84:8d:32:28:93:38:0e:2f:5e:ef:ec:d1:c8:31:3a:78:c9:c5:56:c7:f3:65:be:25:d4:bf:b1:ad:0f:d3:fd:a8:1a:21:f3:a8:6c:fe:9b:77:4a:7c:a9:34:ca:9b:63:06:68:59:b6:81:9c:f3:5d:9f:90:c1:4d:a3:ab:61:51:c1:5c:80:25:0b:5d:68:c1:85:de:fe:2a:73:9c:00:fe:5b:4c:5c:c5:04:b0:33:9a:1f:eb:66:73:fe:5d:ed:fb:d5:13:ee:71:b4:1d:ec:e7:8d:c9:4c:aa:0a:5e:4f:25:cf:0d:ec:fd:85:0e:c7:7b:ce:10:98:26:5a:0a:90:bb:e2:ca:22:69:f8:ee:e7:cb:18:10:23:54:38:bb:54:d8:c6:bf:30:be:10:4b:2e:9f:ae:e4:97:71:68:39:0c:e5:10:b7:2a:06:34:c6:4d:c6:51:e9:fb:e1:ad:0c:dc:5b:a4:5e:9e:52:02:d5:f1:d9:a5:31:d3:b7:7f:4a:2a:f4:1a:b2:5b:de:43:5c:9d:81:f2:39:fc:95:92:3a:d9:7a:c7:2c:3c:77:3a:28:fc:b3:87:ce:59:51:7a:6e:a2:fb:80:e8:16:f5:d3:41:76:30:be:fb:ab:16:9d:e2:d7:8c:16:c9:37" value="497afa0c28063859143976f2c610146c21ad0c87b08b8385d69b1ad1dd4e6f71163aafdb3e59f8419f73ffd3013cbe25cc57b48db2502253adb6afbb6af97fef683519ebce14843948f5d8a92a4fdd8e33144b5247ba94db90e380d68219bfdb73d979d2827486eec1d48b5662379b4fe70310781405c7711e08e95b4373279deab8c96a4d9ebe74bd4e4d0ab703f11f0462a32cf15d0e27c05d25d001cef2f62c9247e6fbab6d5ebdad5ba1f5daa360700d5a98a4094f94615968aad501b50023ff22bc1bd05f36eadb4c9180f62b438d4b1baec7dd14a35ff54d8fb00e881cd2ba2ee9ef8264cbb9d9fb1c7c2b77ee181a265b0c28db778a8497bb3def51bf00495763bb58aa3846eaf2ef00c79150ff7f36b05855c9b4a82f2e338bbcd7dcd56a6959e2eeec8542208c762c3fa2dc07db13954812a7ea7fdefa14bd345b13ab51cb976277c87369f18eecf50f16ce88dab120073a8b8f5b3021ef604bd466d7f1a4218c93de87907890349c0c027a148f4781ee7803be0500b4bc6fe1176e56c08595b41d8a0548cb0d20dc80082c199644012f26ebd4c56d5906eb14fb71f066f33e4fa2c8481414fb7727bdf47331116939a7c23864b5ca82ba953afe71f1a10364b846c5e189debe44da7de1aac7c01d1e28480f122ef867486af1a51a209b4247ed7ce96e8485817058fd5f647ab699951f609d725ab0e0da6a3bce1258b9ba620be414f2f561ff3df5c041b25393c996a9233bfc3fa639406edbe728748e25f9bc4a14b7f5361bfde4ef3a490b4e862230e849d198a6d8d7f19121f0b51023f5e74ad51fe89ff937525175c673fb8f441fa28266173ff40cfbeeebf9067d590b8235acf2550d49abc70e02ee43f6b47c01f4116675b475a3bd2e0bde8880378dbb6a952e1eb12de6ac00a79cff53cf6253946c243b2caf3ee95d599a477110b2831e97c182629f228ad9b5376210fa80abaf4f39d19f0ec350b699f64d2833fb08c9d0cdce1dea3a1805a16c0e18c9fdf03e6e8d53eea582bf30ca98ecf83a2252f33959df4d1d3d080fa6f1d3f5b21be16823bd01c3b164daaf53f82b6df99683b249895dd4eae5c472fcb310ddb43055063c0c5996861bc47504f6286a15a402c7179d100e1cf0ad67eeaffb06417b0bf9629ec886df93a6548c4992e0eb81d0f77caec52a7de1c9f943357db58a0e1ffbe35a9a710e5294da72e4bc3fbee59161cef401969a8e25f36856281d1340ba28f4cd44f92816a490b12219e46be69b247b7de5d7a9e6c627337c8ea0a827a506d7008a3a0b2804f0613977843ecb21fcae3d9febadeef48d28a20c55940557ba79bd1f77f67e5c4631c28a255281821f656661dc32d9bc5d8aa3aef9638e91175ac68dfc5650ab848d322893380e2f5eefecd1c8313a78c9c556c7f365be25d4bfb1ad0fd3fda81a21f3a86cfe9b774a7ca934ca9b63066859b6819cf35d9f90c14da3ab6151c15c80250b5d68c185defe2a739c00fe5b4c5cc504b0339a1feb6673fe5dedfbd513ee71b41dece78dc94caa0a5e4f25cf0decfd850ec77bce1098265a0a90bbe2ca2269f8eee7cb1810235438bb54d8c6bf30be104b2e9faee4977168390ce510b72a0634c64dc651e9fbe1ad0cdc5ba45e9e5202d5f1d9a531d3b77f4a2af41ab25bde435c9d81f239fc95923ad97ac72c3c773a28fcb387ce59517a6ea2fb80e816f5d3417630befbab169de2d78c16c937"/>
    <field name="quic.frame" showname="ACK" size="5" pos="42" show="" value="">
      <field name="quic.frame_type" showname="Frame Type: ACK (0x0000000000000002)" size="1" pos="0" show="2" value="02"/>
      <field name="quic.ack.largest_acknowledged" showname="Largest Acknowledged: 1" size="1" pos="1" show="1" value="01"/>
      <field name="quic.ack.ack_delay" showname="ACK Delay: 0" size="1" pos="2" show="0" value="00"/>
      <field name="quic.ack.ack_range_count" showname="ACK Range Count: 0" size="1" pos="3" show="0" value="00"/>
      <field name="quic.ack.first_ack_range" showname="First ACK Range: 0" size="1" pos="4" show="0" value="00"/>
    </field>
    <field name="quic.frame" showname="CRYPTO" size="94" pos="47" show="" value="">
      <field name="quic.frame_type" showname="Frame Type: CRYPTO (0x0000000000000006)" size="1" pos="5" show="6" value="06"/>
      <field name="quic.crypto.offset" showname="Offset: 0" size="1" pos="6" show="0" value="00"/>
      <field name="quic.crypto.length" showname="Length: 90" size="2" pos="7" show="90" value="405a"/>
      <field name="quic.crypto.crypto_data" showname="Crypto Data" size="90" pos="9" show="" value=""/>
      <proto name="tls" showname="TLSv1.3 Record Layer: Handshake Protocol: Server Hello" size="90" pos="9">
        <field name="tls.handshake" showname="Handshake Protocol: Server Hello" size="90" pos="9" show="" value="">
          <field name="tls.handshake.type" showname="Handshake Type: Server Hello (2)" size="1" pos="9" show="2" value="02"/>
          <field name="tls.handshake.length" showname="Length: 86" size="3" pos="10" show="86" value="000056"/>
          <field name="tls.handshake.version" showname="Version: TLS 1.2 (0x0303)" size="2" pos="13" show="0x0303" value="0303"/>
          <field name="tls.handshake.random" showname="Random: cd983e1b102040fe30155f1f92b115746ebbeb4acc2fcf11f425234e4afddc78" size="32" pos="15" show="cd:98:3e:1b:10:20:40:fe:30:15:5f:1f:92:b1:15:74:6e:bb:eb:4a:cc:2f:cf:11:f4:25:23:4e:4a:fd:dc:78" value="cd983e1b102040fe30155f1f92b115746ebbeb4acc2fcf11f425234e4afddc78"/>
          <field name="tls.handshake.session_id_length" showname="Session ID Length: 0" size="1" pos="47" show="0" value="00"/>
          <field name="tls.handshake.ciphersuite" showname="Cipher Suite: TLS_AES_128_GCM_SHA256 (0x1301)" size="2" pos="48" show="0x1301" value="1301"/>
          <field name="tls.handshake.comp_method" showname="Compression Method: null (0)" size="1" pos="50" show="0" value="00"/>
          <field name="tls.handshake.extensions_length" showname="Extensions Length: 46" size="2" pos="51" show="46" value="002e"/>
          <field name="" show="Extension: key_share (len=36) x25519" size="40" pos="53" value="00330024001d0020ce433603786eab582ce1231af106ff7889690c33c704ef0402252d3fc175a071">
            <field name="tls.handshake.extension.type" showname="Type: key_share (51)" size="2" pos="53" show="51" value="0033"/>
            <field name="tls.handshake.extension.len" showname="Length: 36" size="2" pos="55" show="36" value="0024"/>
            <field name="" show="Key Share extension" size="36" pos="57" value="001d0020ce433603786eab582ce1231af106ff7889690c33c704ef0402252d3fc175a071">
              <field name="" show="Key Share Entry: Group: x25519, Key Exchange length: 32" size="36" pos="57" value="001d0020ce433603786eab582ce1231af106ff7889690c33c704ef0402252d3fc175a071">
                <field name="tls.handshake.extensions_key_share_group" showname="Group: x25519 (29)" size="2" pos="57" show="29" value="001d"/>
                <field name="tls.handshake.extensions_key_share_key_exchange_length" showname="Key Exchange Length: 32" size="2" pos="59" show="32" value="0020"/>
                <field name="tls.handshake.extensions_key_share_key_exchange" showname="Key Exchange: ce433603786eab582ce1231af106ff7889690c33c704ef0402252d3fc175a071" size="32" pos="61" show="ce:43:36:03:78:6e:ab:58:2c:e1:23:1a:f1:06:ff:78:89:69:0c:33:c7:04:ef:04:02:25:2d:3f:c1:75:a0:71" value="ce433603786eab582ce1231af106ff7889690c33c704ef0402252d3fc175a071"/>
              </field>
            </field>
          </field>
          <field name="" show="Extension: supported_versions (len=2) TLS 1.3" size="6" pos="93" value="002b00020304">
            <field name="tls.handshake.extension.type" showname="Type: supported_versions (43)" size="2" pos="93" show="43" value="002b"/>
            <field name="tls.handshake.extension.len" showname="Length: 2" size="2" pos="95" show="2" value="0002"/>
            <field name="tls.handshake.extensions.supported_version" showname="Supported Version: TLS 1.3 (0x0304)" size="2" pos="97" show="0x0304" value="0304"/>
          </field>
          <field name="tls.handshake.ja3s_full" showname="JA3S Fullstring: 771,4865,51-43" size="0" pos="51" show="771,4865,51-43"/>
          <field name="tls.handshake.ja3s" showname="JA3S: eb1d94daa7e0344597e756a1fb6e7054" size="0" pos="51" show="eb1d94daa7e0344597e756a1fb6e7054"/>
        </field>
      </proto>
    </field>
    <field name="quic.payload" showname="PADDING Length: 1116" size="1116" pos="99" show="" value="">
      <field name="quic.frame_type" showname="Frame Type: PADDING (0x0000000000000000)" size="1" pos="99" show="0" value="00"/>
      <field name="quic.padding_length" showname="Padding Length: 1116" size="0" pos="100" show="1116"/>
    </field>
  </proto>
         </packet>
        </pdml>"#;

        let mut reader = quick_xml::Reader::from_reader(BufReader::new(xml.as_bytes()));
        match parse_xml(&mut reader, &[]).unwrap() {
            Some(p) => match p.layer_name("quic") {
                Some(layer) => {
                    let metadata_name = "quic.payload";
                    layer
                        .metadata(metadata_name)
                        .unwrap_or_else(|| panic!("Missing {}", metadata_name));

                    let metadata_name = "quic.padding_length";
                    layer
                        .metadata(metadata_name)
                        .unwrap_or_else(|| panic!("Missing {}", metadata_name));
                }
                None => panic!("missing protocol"),
            },
            _ => panic!("invalid Output type"),
        }
    }

    #[test]
    fn test_rtshark_input_pcap() {
        let pcap = include_bytes!("test.pcap");

        // create temp dir and copy pcap in it
        let tmp_dir = tempdir::TempDir::new("test_pcap").unwrap();
        let pcap_path = tmp_dir.path().join("file.pcap");
        let mut output = std::fs::File::create(&pcap_path).expect("unable to open file");
        output.write_all(pcap).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        // spawn tshark on it
        let builder = RTSharkBuilder::builder().input_path(pcap_path.to_str().unwrap());

        let mut rtshark = builder.spawn().unwrap();

        // read a packet
        match rtshark.read().unwrap() {
            Some(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }

        loop {
            match rtshark.read().unwrap() {
                None => break,
                Some(_) => todo!(),
            }
        }

        rtshark.kill();

        assert!(rtshark.pid().is_none());

        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[test]
    fn test_rtshark_input_pcap_decode_as() {
        // 0. prepare pcap
        let pcap = include_bytes!("http2.pcap");

        // create temp dir and copy pcap in it
        let tmp_dir = tempdir::TempDir::new("test_pcap").unwrap();
        let pcap_path = tmp_dir.path().join("http2.pcap");
        let mut output = std::fs::File::create(&pcap_path).expect("unable to open file");
        output.write_all(pcap).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        // 1. a first run without decode_as option

        // spawn tshark on it
        let builder = RTSharkBuilder::builder().input_path(pcap_path.to_str().unwrap());

        let mut rtshark = builder.spawn().unwrap();

        // read a packet, must be tcp without http2
        match rtshark.read().unwrap() {
            Some(p) => assert!(p.layer_name("http2").is_none()),
            _ => panic!("invalid Output type"),
        }

        rtshark.kill();

        assert!(rtshark.pid().is_none());

        // 2. a second run with decode_as option
        let builder = RTSharkBuilder::builder()
            .input_path(pcap_path.to_str().unwrap())
            .decode_as("tcp.port==29502,http2");

        let mut rtshark = builder.spawn().unwrap();

        // read a packet, must be http2
        match rtshark.read().unwrap() {
            Some(p) => assert!(p.layer_name("http2").is_some()),
            _ => panic!("invalid Output type"),
        }

        rtshark.kill();

        assert!(rtshark.pid().is_none());

        // 3. cleanup
        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[test]
    fn test_rtshark_input_pcap_display_filter() {
        let pcap = include_bytes!("test.pcap");

        // create temp dir and copy pcap in it
        let tmp_dir = tempdir::TempDir::new("test_pcap").unwrap();
        let pcap_path = tmp_dir.path().join("file.pcap");
        let mut output = std::fs::File::create(&pcap_path).expect("unable to open file");
        output.write_all(pcap).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        // first pass: get a udp packet
        let builder = RTSharkBuilder::builder()
            .input_path(pcap_path.to_str().unwrap())
            .display_filter("udp.port == 53");

        let mut rtshark = builder.spawn().unwrap();

        // read a packet
        match rtshark.read().unwrap() {
            Some(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }

        rtshark.kill();

        // second pass: try a tcp packet
        let builder = RTSharkBuilder::builder()
            .input_path(pcap_path.to_str().unwrap())
            .display_filter("tcp.port == 80");

        let mut rtshark = builder.spawn().unwrap();

        // we should get EOF since no packet is matching
        match rtshark.read().unwrap() {
            None => (),
            _ => panic!("invalid Output type"),
        }

        rtshark.kill();

        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[test]
    fn test_rtshark_input_pcap_blacklist() {
        let pcap = include_bytes!("test.pcap");

        // create temp dir and copy pcap in it
        let tmp_dir = tempdir::TempDir::new("test_pcap").unwrap();
        let pcap_path = tmp_dir.path().join("file.pcap");
        let mut output = std::fs::File::create(&pcap_path).expect("unable to open file");
        output.write_all(pcap).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        // spawn tshark on it
        let builder = RTSharkBuilder::builder()
            .input_path(pcap_path.to_str().unwrap())
            .metadata_blacklist("ip.src");
        let mut rtshark = builder.spawn().unwrap();

        // read a packet
        let pkt = match rtshark.read().unwrap() {
            Some(p) => p,
            _ => panic!("invalid Output type"),
        };

        let ip = pkt.layer_name("ip").unwrap();
        assert!(ip.metadata("ip.src").is_none());
        assert!(ip.metadata("ip.dst").unwrap().value().eq("127.0.0.1"));

        rtshark.kill();

        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[test]
    fn test_rtshark_input_pcap_whitelist() {
        let pcap = include_bytes!("test.pcap");

        // create temp dir and copy pcap in it
        let tmp_dir = tempdir::TempDir::new("test_pcap").unwrap();
        let pcap_path = tmp_dir.path().join("file.pcap");
        let mut output = std::fs::File::create(&pcap_path).expect("unable to open file");
        output.write_all(pcap).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        // spawn tshark on it
        let builder = RTSharkBuilder::builder()
            .input_path(pcap_path.to_str().unwrap())
            .metadata_whitelist("ip.dst");
        let mut rtshark = builder.spawn().unwrap();

        // read a packet
        let pkt = match rtshark.read().unwrap() {
            Some(p) => p,
            _ => panic!("invalid Output type"),
        };

        let ip = pkt.layer_name("ip").unwrap();
        assert!(ip.metadata("ip.src").is_none());
        assert!(ip.metadata("ip.dst").unwrap().value().eq("127.0.0.1"));

        rtshark.kill();

        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[test]
    fn test_rtshark_input_pcap_multiple_whitelist() {
        let pcap = include_bytes!("test.pcap");

        // create temp dir and copy pcap in it
        let tmp_dir = tempdir::TempDir::new("test_pcap").unwrap();
        let pcap_path = tmp_dir.path().join("file.pcap");
        let mut output = std::fs::File::create(&pcap_path).expect("unable to open file");
        output.write_all(pcap).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        // spawn tshark on it
        let builder = RTSharkBuilder::builder()
            .input_path(pcap_path.to_str().unwrap())
            .metadata_whitelist("ip.src")
            .metadata_whitelist("ip.dst");
        let mut rtshark = builder.spawn().unwrap();

        // read a packet
        let pkt = match rtshark.read().unwrap() {
            Some(p) => p,
            _ => panic!("invalid Output type"),
        };

        let ip = pkt.layer_name("ip").unwrap();
        assert!(ip.metadata("ip.src").unwrap().value().eq("127.0.0.1"));
        assert!(ip.metadata("ip.dst").unwrap().value().eq("127.0.0.1"));

        rtshark.kill();

        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[test]
    fn test_rtshark_input_pcap_whitelist_multiple_layer() {
        let pcap = include_bytes!("test.pcap");

        // create temp dir and copy pcap in it
        let tmp_dir = tempdir::TempDir::new("test_pcap").unwrap();
        let pcap_path = tmp_dir.path().join("file.pcap");
        let mut output = std::fs::File::create(&pcap_path).expect("unable to open file");
        output.write_all(pcap).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        // spawn tshark on it
        let builder = RTSharkBuilder::builder()
            .input_path(pcap_path.to_str().unwrap())
            .metadata_whitelist("ip.src")
            .metadata_whitelist("udp.dstport");
        let mut rtshark = builder.spawn().unwrap();

        // read a packet
        let pkt = match rtshark.read().unwrap() {
            Some(p) => p,
            _ => panic!("invalid Output type"),
        };

        let ip = pkt.layer_name("ip").unwrap();
        assert!(ip.metadata("ip.src").unwrap().value().eq("127.0.0.1"));
        let ip = pkt.layer_name("udp").unwrap();
        assert!(ip.metadata("udp.dstport").unwrap().value().eq("53"));

        rtshark.kill();

        tmp_dir.close().expect("Error deleting fifo dir");
    }

    // this test may fail if executed in parallel with other tests. Run `cargo test --  --test-threads=1`.
    #[test]
    fn test_rtshark_input_pcap_whitelist_missing_attr() {
        let pcap = include_bytes!("test.pcap");

        // create temp dir and copy pcap in it
        let tmp_dir = tempdir::TempDir::new("test_pcap").unwrap();
        let pcap_path = tmp_dir.path().join("file.pcap");
        let mut output = std::fs::File::create(&pcap_path).expect("unable to open file");
        output.write_all(pcap).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        // spawn tshark on it
        let builder = RTSharkBuilder::builder()
            .input_path(pcap_path.to_str().unwrap())
            .metadata_whitelist("nosuchproto.nosuchmetadata");
        let mut rtshark = builder.spawn().unwrap();

        // read a packet
        let ret = rtshark.read();
        assert!(ret.is_err());

        rtshark.kill();

        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn test_rtshark_input_fifo() {
        let pcap = include_bytes!("test.pcap");

        // create temp dir
        let tmp_dir = tempdir::TempDir::new("test_fifo").unwrap();
        let fifo_path = tmp_dir.path().join("pcap.pipe");

        // create new fifo and give read, write and execute rights to the owner
        nix::unistd::mkfifo(&fifo_path, nix::sys::stat::Mode::S_IRWXU)
            .expect("Error creating fifo");

        // start tshark on the fifo
        let builder = RTSharkBuilder::builder()
            .input_path(fifo_path.to_str().unwrap())
            .live_capture();
        let mut rtshark = builder.spawn().unwrap();

        // send packets in the fifo
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .open(&fifo_path)
            .expect("unable to open fifo");
        output.write_all(pcap).expect("unable to write in fifo");

        // get analysis
        match rtshark.read().unwrap() {
            Some(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }

        // stop tshark
        rtshark.kill();

        // verify tshark is stopped
        assert!(rtshark.pid().is_none());

        /* remove fifo & tempdir */
        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn test_rtshark_input_pcap_filter_pcap() {
        let pcap = include_bytes!("test.pcap");

        // create temp dir
        let tmp_dir = tempdir::TempDir::new("test_fifo").unwrap();
        let fifo_path = tmp_dir.path().join("pcap.pipe");

        // create new fifo and give read, write and execute rights to the owner
        nix::unistd::mkfifo(&fifo_path, nix::sys::stat::Mode::S_IRWXU)
            .expect("Error creating fifo");

        // first, check with the right filter, we get the packet
        let builder = RTSharkBuilder::builder()
            .input_path(fifo_path.to_str().unwrap())
            .live_capture()
            .capture_filter("port 53");

        let mut rtshark = builder.spawn().unwrap();

        // send packets in the fifo
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .open(&fifo_path)
            .expect("unable to open fifo");
        output.write_all(pcap).expect("unable to write in fifo");

        // read a packet
        match rtshark.read().unwrap() {
            Some(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }

        rtshark.kill();

        assert!(rtshark.pid().is_none());

        // then, check with the bad filter, we don't get the packet
        // TODO (need a pcap with 2 packets, first will be filtered out)

        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn test_rtshark_drop() {
        // create temp dir
        let tmp_dir = tempdir::TempDir::new("test_fifo").unwrap();
        let fifo_path = tmp_dir.path().join("pcap.pipe");

        // create new fifo and give read, write and execute rights to the owner
        nix::unistd::mkfifo(&fifo_path, nix::sys::stat::Mode::S_IRWXU)
            .expect("Error creating fifo");

        // start tshark on the fifo
        let builder = RTSharkBuilder::builder()
            .input_path(fifo_path.to_str().unwrap())
            .live_capture();

        let mut sys = sysinfo::System::new_all();

        let pid = {
            let rtshark = builder.spawn().unwrap();
            let pid = rtshark.pid().unwrap();

            // assert!(std::path::Path::new(&format!("/proc/{pid}")).exists());
            sys.refresh_all();
            assert!(sys.process(sysinfo::Pid::from_u32(pid)).is_some());
            pid
        };

        // verify tshark is stopped
        sys.refresh_all();
        // assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
        assert!(sys.process(sysinfo::Pid::from_u32(pid)).is_none());

        /* remove fifo & tempdir */
        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn test_rtshark_killed() {
        // create temp dir
        let tmp_dir = tempdir::TempDir::new("test_fifo").unwrap();
        let fifo_path = tmp_dir.path().join("pcap.pipe");

        // create new fifo and give read, write and execute rights to the owner
        nix::unistd::mkfifo(&fifo_path, nix::sys::stat::Mode::S_IRWXU)
            .expect("Error creating fifo");

        // start tshark on the fifo
        let builder = RTSharkBuilder::builder()
            .input_path(fifo_path.to_str().unwrap())
            .live_capture();

        let mut rtshark = builder.spawn().unwrap();

        // killing badly
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(rtshark.pid().unwrap() as libc::pid_t),
            nix::sys::signal::Signal::SIGKILL,
        )
        .unwrap();

        // reading from process output should give EOF
        match rtshark.read().unwrap() {
            None => (),
            _ => panic!("invalid Output type"),
        }

        /* remove fifo & tempdir */
        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn test_rtshark_fifo_lost() {
        // create temp dir
        let tmp_dir = tempdir::TempDir::new("test_fifo").unwrap();
        let fifo_path = tmp_dir.path().join("pcap.pipe");

        // create new fifo and give read, write and execute rights to the owner
        nix::unistd::mkfifo(&fifo_path, nix::sys::stat::Mode::S_IRWXU)
            .expect("Error creating fifo");

        // start tshark on the fifo
        let builder = RTSharkBuilder::builder()
            .input_path(fifo_path.to_str().unwrap())
            .live_capture();

        let mut rtshark = builder.spawn().unwrap();

        /* remove fifo & tempdir */
        tmp_dir.close().expect("Error deleting fifo dir");

        // reading from process output should give 2 error messages then EOF
        loop {
            match rtshark.read() {
                Ok(e) if e.is_some() => panic!("invalid Output type"),
                Ok(e) if e.is_none() => break,
                _ => (),
            }
        }
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn test_rtshark_fifo_opened_then_closed() {
        let pcap = include_bytes!("test.pcap");

        // create temp dir
        let tmp_dir = tempdir::TempDir::new("test_fifo").unwrap();
        let fifo_path = tmp_dir.path().join("pcap.pipe");

        // create new fifo and give read, write and execute rights to the owner
        nix::unistd::mkfifo(&fifo_path, nix::sys::stat::Mode::S_IRWXU)
            .expect("Error creating fifo");

        // start tshark on the fifo
        let builder = RTSharkBuilder::builder()
            .input_path(fifo_path.to_str().unwrap())
            .live_capture();

        let mut rtshark = builder.spawn().unwrap();

        // send packets in the fifo then close it immediately
        {
            let mut output = std::fs::OpenOptions::new()
                .write(true)
                .open(&fifo_path)
                .expect("unable to open fifo");
            output.write_all(pcap).expect("unable to write in fifo");
        }

        // get analysis
        match rtshark.read().unwrap() {
            Some(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }

        // disable this check for now - fails due to "normal" error message on stderr when tshark stops:
        // ---- tests::test_rtshark_fifo_opened_then_closed stdout ----
        // thread 'tests::test_rtshark_fifo_opened_then_closed' panicked at 'called `Result::unwrap()` on an `Err` value: Custom { kind: InvalidInput, error: "1 packet captured\n" }', src/lib.rs:1924:30
        // note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
        /*
        match rtshark.read().unwrap() {
            None => (),
            _ => panic!("invalid Output type"),
        }
        */

        // stop tshark
        rtshark.kill();

        // reading from process output should give EOF
        // disable this check for now - fails due to "normal" error message on stderr when tshark stops:
        // ---- tests::test_rtshark_fifo_opened_then_closed stdout ----
        // thread 'tests::test_rtshark_fifo_opened_then_closed' panicked at 'called `Result::unwrap()` on an `Err` value: Custom { kind: InvalidInput, error: "tshark: \n" }', src/lib.rs:1969:30
        // note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace

        /*
        match rtshark.read().unwrap() {
            None => (),
            _ => panic!("invalid Output type"),
        }
        */

        /* remove fifo & tempdir */
        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[test]
    fn test_rtshark_file_missing() {
        // start tshark on a missing fifo
        let builder = RTSharkBuilder::builder().input_path("/missing/rtshark/fifo");

        let ret = builder.spawn();

        match ret {
            Ok(_) => panic!("We can't start if file is missing"),
            Err(e) => println!("{e}"),
        }
    }

    #[test]
    #[serial] // Run test serially since its modifying env PATH
    fn test_rtshark_tshark_missing() {
        // clear PATH env (if tshark is already in PATH)
        let path = match std::env::var("PATH") {
            Ok(v) => {
                std::env::remove_var("PATH");
                Some(v)
            }
            Err(_) => None,
        };

        // start tshark on a missing fifo
        let builder = RTSharkBuilder::builder()
            .input_path("/missing/rtshark/fifo")
            .live_capture()
            .env_path("/invalid/path");

        let ret = builder.spawn();

        // restore PATH env (for other tests)
        if let Some(v) = path {
            std::env::set_var("PATH", v);
        }

        match ret {
            Ok(_) => panic!("We can't start if tshark is missing"),
            Err(e) => println!("{e}"),
        }
    }

    #[test]
    fn test_rtshark_input_pcap_output_pcap() {
        let pcap = include_bytes!("test.pcap");

        // create temp dir and copy pcap in it
        let tmp_dir = tempdir::TempDir::new("test_pcap").unwrap();
        let in_path = tmp_dir.path().join("in.pcap");
        let mut output = std::fs::File::create(&in_path).expect("unable to open file");
        output.write_all(pcap).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        let out_path = tmp_dir.path().join("out.pcap");

        // spawn tshark on it
        let builder = RTSharkBuilder::builder()
            .input_path(in_path.to_str().unwrap())
            .output_path(out_path.to_str().unwrap());

        let mut rtshark = builder.spawn().unwrap();

        // read a packet
        match rtshark.read().unwrap() {
            Some(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }

        loop {
            match rtshark.read().unwrap() {
                None => break,
                Some(_) => todo!(),
            }
        }

        rtshark.kill();

        assert!(rtshark.pid().is_none());

        // now check what was written
        let mut rtshark = RTSharkBuilder::builder()
            .input_path(out_path.to_str().unwrap())
            .spawn()
            .unwrap();

        // read a packet
        match rtshark.read().unwrap() {
            Some(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }

        rtshark.kill();

        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn test_rtshark_input_fifo_output_pcap() {
        let pcap = include_bytes!("test.pcap");

        // create temp dir
        let tmp_dir = tempdir::TempDir::new("test_fifo").unwrap();
        let fifo_path = tmp_dir.path().join("pcap.pipe");

        // create new fifo and give read, write and execute rights to the owner
        nix::unistd::mkfifo(&fifo_path, nix::sys::stat::Mode::S_IRWXU)
            .expect("Error creating fifo");

        let out_path = tmp_dir.path().join("out.pcap");

        // start tshark on the fifo
        let builder = RTSharkBuilder::builder()
            .input_path(fifo_path.to_str().unwrap())
            .output_path(out_path.to_str().unwrap())
            .live_capture();
        let mut rtshark = builder.spawn().unwrap();

        // send packets in the fifo
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .open(&fifo_path)
            .expect("unable to open fifo");
        output.write_all(pcap).expect("unable to write in fifo");

        // get analysis
        match rtshark.read().unwrap() {
            Some(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }

        // stop tshark
        rtshark.kill();

        // verify tshark is stopped
        assert!(rtshark.pid().is_none());

        // now check what was written
        let mut rtshark = RTSharkBuilder::builder()
            .input_path(out_path.to_str().unwrap())
            .spawn()
            .unwrap();

        // read a packet
        match rtshark.read().unwrap() {
            Some(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }

        rtshark.kill();

        /* remove fifo & tempdir */
        tmp_dir.close().expect("Error deleting fifo dir");
    }
    #[test]
    #[serial] // Run test serially to limit check to multiple spawns in test
    fn test_rtshark_multiple_spawn_pcap() {
        let pcap = include_bytes!("test.pcap");

        // create temp dir and copy pcap in it
        let tmp_dir = tempdir::TempDir::new("test_pcap").unwrap();
        let in_path = tmp_dir.path().join("in.pcap");
        let mut output = std::fs::File::create(&in_path).expect("unable to open file");
        output.write_all(pcap).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        let out_path = tmp_dir.path().join("out.pcap");

        // spawn tshark on it
        let builder = RTSharkBuilder::builder()
            .input_path(in_path.to_str().unwrap())
            .output_path(out_path.to_str().unwrap());

        let mut rtshark = builder.spawn().unwrap();

        // read a packet
        match rtshark.read().unwrap() {
            Some(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }

        rtshark.kill();

        // retry
        let mut rtshark = builder.spawn().unwrap();

        // read a packet
        match rtshark.read().unwrap() {
            Some(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }

        rtshark.kill();

        /* remove fifo & tempdir */
        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[test]
    fn test_rtshark_timestamp_micros() {
        let pcap = include_bytes!("test.pcap");

        // create temp dir and copy pcap in it
        let tmp_dir = tempdir::TempDir::new("test_pcap").unwrap();
        let in_path = tmp_dir.path().join("in.pcap");
        let mut output = std::fs::File::create(&in_path).expect("unable to open file");
        output.write_all(pcap).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        let out_path = tmp_dir.path().join("out.pcap");

        // spawn tshark on it
        let builder = RTSharkBuilder::builder()
            .input_path(in_path.to_str().unwrap())
            .output_path(out_path.to_str().unwrap());

        let mut rtshark = builder.spawn().unwrap();

        // read a packet
        match rtshark.read().unwrap() {
            Some(p) => assert_eq!(p.timestamp_micros(), Some(1652011560275852)),
            _ => panic!("invalid Output type"),
        }

        rtshark.kill();

        /* remove fifo & tempdir */
        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[test]
    fn test_rtshark_tls_keylogfile_pcap() {
        let pcap = include_bytes!("test_tls.pcap");
        let keylog = include_bytes!("test_tlskeylogfile.txt");

        // create temp dir and copy pcap in it
        let tmp_dir = tempdir::TempDir::new("test_pcap").unwrap();
        let pcap_path = tmp_dir.path().join("file.pcap");
        let mut output = std::fs::File::create(&pcap_path).expect("unable to open file");
        output.write_all(pcap).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        // spawn tshark on it
        let builder = RTSharkBuilder::builder().input_path(pcap_path.to_str().unwrap());

        let mut rtshark = builder.spawn().unwrap();

        // read packets
        loop {
            match rtshark.read().unwrap() {
                None => break,
                Some(p) => {
                    // we check there is no visible http2
                    assert!(p.layer_name("tcp").is_some());
                    assert!(p.layer_name("http2").is_none())
                }
            }
        }

        rtshark.kill();

        let keylog_path = tmp_dir.path().join("keylogfile.txt");
        let mut output = std::fs::File::create(&keylog_path).expect("unable to open file");
        output.write_all(keylog).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        let builder = RTSharkBuilder::builder()
            .input_path(pcap_path.to_str().unwrap())
            .keylog_file(keylog_path.as_os_str().to_str().unwrap());

        let mut rtshark = builder.spawn().unwrap();

        // read packets and search for http2 get
        let mut http2_get_found = false;
        loop {
            match rtshark.read().unwrap() {
                None => break,
                Some(p) => {
                    // we check there is a http2 method GET
                    assert!(p.layer_name("tcp").is_some());
                    if let Some(http2) = p.layer_name("http2") {
                        if let Some(get) = http2.metadata("http2.headers.method") {
                            if get.value() == "GET" {
                                http2_get_found = true;
                            }
                        }
                    }
                }
            }
        }

        assert!(http2_get_found);

        rtshark.kill();

        assert!(rtshark.pid().is_none());
        tmp_dir.close().expect("Error deleting fifo dir");
    }
}
