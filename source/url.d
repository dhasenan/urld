/**
	* A URL handling library.
	*
	* URLs are Unique Resource Locators. They consist of a scheme and a host, with some optional
	* elements like port, path, username, and password.
	*
	* This module aims to make it simple to muck about with them.
	*
	* Example usage:
	* ---
	* auto url = "ssh://me:password@192.168.0.8/".parseURL;
	* auto files = system("ssh", url.toString, "ls").splitLines;
	* foreach (file; files) {
	*		auto fileURL = url;
	*		fileURL.path = file;
	*		system("scp", fileURL.toString, ".");
	* }
	* ---
	*/
module url;

import std.algorithm;
import std.array;
import std.conv;
import std.encoding;
import std.string;
import std.utf;

/// An exception thrown when something bad happens with URLs.
class URLException : Exception {
	this(string msg) { super(msg); }
}

/**
	* A mapping from schemes to their default ports.
	*
  * This is not exhaustive. Not all schemes use ports. Not all schemes uniquely identify a port to
	* use even if they use ports. Entries here should be treated as best guesses.
  */
ushort[string] schemeToDefaultPort;

static this() {
	schemeToDefaultPort = [
		"aaa": 3868,
		"aaas": 5658,
		"acap": 674,
		"cap": 1026,
		"coap": 5683,
		"coaps": 5684,
		"dav": 443,
		"dict": 2628,
		"ftp": 21,
		"git": 9418,
		"go": 1096,
		"gopher": 70,
		"http": 80,
		"https": 443,
		"iac": 4569,
		"icap": 1344,
		"imap": 143,
		"ipp": 631,
		"ipps": 631,  // yes, they're both mapped to port 631
		"irc": 6667,  // De facto default port, not the IANA reserved port.
		"ircs": 6697,
		"iris": 702,  // defaults to iris.beep
		"iris.beep": 702,
		"iris.lwz": 715,
		"iris.xpc": 713,
		"iris.xpcs": 714,
		"jabber": 5222,  // client-to-server
		"ldap": 389,
		"ldaps": 636,
		"msrp": 2855,
		"msrps": 2855,
		"mtqp": 1038,
		"mupdate": 3905,
		"news": 119,
		"nfs": 2049,
		"pop": 110,
		"redis": 6379,
		"reload": 6084,
		"rsync": 873,
		"rtmfp": 1935,
		"rtsp": 554,
		"shttp": 80,
		"sieve": 4190,
		"sip": 5060,
		"sips": 5061,
		"smb": 445,
		"smtp": 25,
		"snews": 563,
		"snmp": 161,
		"soap.beep": 605,
		"ssh": 22,
		"stun": 3478,
		"stuns": 5349,
		"svn": 3690,
		"teamspeak": 9987,
		"telnet": 23,
		"tftp": 69,
		"tip": 3372,
	];
}

/**
	* A Unique Resource Locator.
	*
	* The syntax for URLs is scheme:[//[user:password@]host[:port]][/]path[?query][#fragment].
	* 
	*/
struct URL {
	/// The URL scheme. For instance, ssh, ftp, or https.
	string scheme;

	/// The username in this URL. Usually absent. If present, there will also be a password.
	string user;

	/// The password in this URL. Usually absent.
	string pass;

	/// The hostname.
	string host;

	/// The port.
	/// This is inferred from the scheme if it isn't present in the URL itself.
	/// If the scheme is not known and the port is not present, the port will be given as 0.
	/// For some schemes, port will not be sensible -- for instance, file or chrome-extension.
	///
	/// If you explicitly need to detect whether the user provided a port, check the providedPort
	/// field.
	@property ushort port() {
		if (providedPort != 0) {
			return providedPort;
		}
		if (auto p = scheme in schemeToDefaultPort) {
			return *p;
		}
		return 0;
	}

	/// Set the port.
	/// This is a shortcut for convenience because you probably don't care about the difference
	/// between port and providedPort.
	@property ushort port(ushort value) {
		return providedPort = value;
	}

	/// The port that was explicitly provided in the URL.
	/// 
	ushort providedPort;

	/// The path. This excludes the query string.
	/// For instance, in the URL https://cnn.com/news/story/17774?visited=false, the path is
	/// "/news/story/17774".
	string path;

	/// The query string elements.
	/// For instance, in the URL https://cnn.com/news/story/17774?visited=false, the query string
	/// elements will be ["visited": "false"].
	/// Similarly, in the URL https://bbc.co.uk/news?item, the query string elements will be
	/// ["item": ""].
	///
	/// This field is mutable. (There is no alternative in this case.) So be cautious.
	string[string] query;

	/// The fragment. In web documents, this typically refers to an anchor element.
	/// For instance, in the URL https://cnn.com/news/story/17774#header2, the fragment is "header2".
	string fragment;

	/// Convert this URL to a string.
	/// The string is properly formatted and usable for, eg, a web request.
	string toString() {
		Appender!string s;
		s ~= scheme;
		s ~= "://";
		if (user) {
			s ~= user.percentEncode;
			s ~= ":";
			s ~= pass.percentEncode;
			s ~= "@";
		}
		s ~= host;
		if (providedPort) {
			if ((scheme in schemeToDefaultPort) == null || schemeToDefaultPort[scheme] != providedPort) {
				s ~= ":";
				s ~= providedPort.to!string;
			}
		}
		string p = path;
		if (p.length == 0) {
			s ~= '/';
		} else {
			if (p[0] == '/') {
				p = p[1..$];
			}
			foreach (part; p.split('/')) {
				s ~= '/';
				s ~= part.percentEncode;
			}
		}
		if (query) {
			s ~= '?';
			bool first = true;
			foreach (k, v; query) {
				if (!first) {
					s ~= '&';
				}
				first = false;
				s ~= k.percentEncode;
				if (v) {
					s ~= '=';
					s ~= v.percentEncode;
				}
			}
		}
		if (fragment) {
			s ~= '#';
			s ~= fragment.percentEncode;
		}
		return s.data;
	}

	/**
		* The append operator (~).
		*
		* The append operator for URLs returns a new URL with the given string appended as a path
		* element to the URL's path. It only adds new path elements (or sequences of path elements).
		*
		* Don't worry about path separators; whether you include them or not, it will just work.
		*
		* Query elements are copied.
		*
		* Examples:
		* ---
		* auto random = "http://testdata.org/random".parseURL;
		* auto randInt = random ~ "int";
		* writeln(randInt);  // prints "http://testdata.org/random/int"
		* ---
		*/
	URL opBinary(string op : "~")(string subsequentPath) {
		URL other = this;
		other ~= subsequentPath;
		if (query) {
			other.query = other.query.dup;
		}
		return other;
	}

	/**
		* The append-in-place operator (~=).
		*
		* The append operator for URLs adds a path element to this URL. It only adds new path elements
		* (or sequences of path elements).
		*
		* Don't worry about path separators; whether you include them or not, it will just work.
		*
		* Examples:
		* ---
		* auto random = "http://testdata.org/random".parseURL;
		* random ~= "int";
		* writeln(random);  // prints "http://testdata.org/random/int"
		* ---
		*/
	URL opOpAssign(string op : "~")(string subsequentPath) {
		if (path.endsWith("/") || subsequentPath.startsWith("/")) {
			if (path.endsWith("/") && subsequentPath.startsWith("/")) {
				path ~= subsequentPath[1..$];
			} else {
				path ~= subsequentPath;
			}
		} else {
			path ~= '/';
			path ~= subsequentPath;
		}
		return this;
	}
}

/**
	* Parse a URL from a string.
	*
	* This attempts to parse a wide range of URLs as people might actually type them. Some mistakes
	* may be made. However, any URL in a correct format will be parsed correctly.
	*
	* Punycode is not supported.
	*/
bool tryParseURL(string value, out URL url) {
	url = URL.init;
	// scheme:[//[user:password@]host[:port]][/]path[?query][#fragment]
	// Scheme is optional in common use. We infer 'http' if it's not given.
	auto i = value.indexOf("://");
	if (i > -1) {
		url.scheme = value[0..i];
		value = value[i+3 .. $];
	} else {
		url.scheme = "http";
	}
	// [user:password@]host[:port]][/]path[?query][#fragment
	i = value.indexOfAny([':', '/']);
	if (i == -1) {
		// Just a hostname.
		url.host = value;
		return true;
	}

	if (value[i] == ':') {
		// This could be between username and password, or it could be between host and port.
		auto j = value.indexOfAny(['@', '/']);
		if (j > -1 && value[j] == '@') {
			try {
				url.user = value[0..i].percentDecode;
				url.pass = value[i+1 .. j].percentDecode;
			} catch (URLException) {
				return false;
			}
			value = value[j+1 .. $];
		}
	}

	// It's trying to be a host/port, not a user/pass.
	i = value.indexOfAny([':', '/']);
	if (i == -1) {
		url.host = value;
		return true;
	}
	url.host = value[0..i];
	value = value[i .. $];
	if (value[0] == ':') {
		auto end = value.indexOf('/');
		if (end == -1) {
			end = value.length;
		}
		try {
			url.port = value[1 .. end].to!ushort;
		} catch (ConvException) {
			return false;
		}
		value = value[end .. $];
		if (value.length == 0) {
			return true;
		}
	}

	i = value.indexOfAny("?#");
	if (i == -1) {
		url.path = value;
		return true;
	}

	try {
		url.path = value[0..i].percentDecode;
	} catch (URLException) {
		return false;
	}
	auto c = value[i];
	value = value[i + 1 .. $];
	if (c == '?') {
		i = value.indexOf('#');
		string query;
		if (i < 0) {
			query = value;
			value = null;
		} else {
			query = value[0..i];
			value = value[i + 1 .. $];
		}
		auto queries = query.split('&');
		foreach (q; queries) {
			auto j = q.indexOf('=');
			try {
				if (j == -1) {
					url.query[q.percentDecode] = "";
				} else {
					url.query[q[0..j].percentDecode] = q[j + 1 .. $].percentDecode;
				}
			} catch (URLException) {
				return false;
			}
		}
	}

	try {
		url.fragment = value.percentDecode;
	} catch (URLException) {
		return false;
	}

	return true;
}

///
unittest {
	{
		// Basic.
		URL url;
		with (url) {
			scheme = "https";
			host = "example.org";
			path = "/foo/bar";
			query["hello"] = "world";
			query["gibe"] = "clay";
			fragment = "frag";
		}
		assert(
				// Not sure what order it'll come out in.
				url.toString == "https://example.org/foo/bar?hello=world&gibe=clay#frag" ||
				url.toString == "https://example.org/foo/bar?gibe=clay&hello=world#frag",
				url.toString);
	}
	{
		// Percent encoded.
		URL url;
		with (url) {
			scheme = "https";
			host = "example.org";
			path = "/f☃o";
			query["❄"] = "❀";
			query["["] = "]";
			fragment = "ş";
		}
		assert(
				// Not sure what order it'll come out in.
				url.toString == "https://example.org/f%E2%98%83o?%E2%9D%84=%E2%9D%80&%5B=%5D#%C5%9F" ||
				url.toString == "https://example.org/f%E2%98%83o?%5B=%5D&%E2%9D%84=%E2%9D%80#%C5%9F",
				url.toString);
	}
	{
		// Port, user, pass.
		URL url;
		with (url) {
			scheme = "https";
			host = "example.org";
			user = "dhasenan";
			pass = "itsasecret";
			port = 17;
		}
		assert(
				url.toString == "https://dhasenan:itsasecret@example.org:17/",
				url.toString);
	}
	{
		// Query with no path.
		URL url;
		with (url) {
			scheme = "https";
			host = "example.org";
			query["hi"] = "bye";
		}
		assert(
				url.toString == "https://example.org/?hi=bye",
				url.toString);
	}
}

///
unittest {
	// There's an existing path.
	auto url = parseURL("http://example.org/foo");
	// No slash? Assume it needs a slash.
	assert((url ~ "bar").toString == "http://example.org/foo/bar");
	// With slash? Don't add another.
	assert((url ~ "/bar").toString == "http://example.org/foo/bar");
	url ~= "bar";
	assert(url.toString == "http://example.org/foo/bar");

	// Path already ends with a slash; don't add another.
	url = parseURL("http://example.org/foo/");
	assert((url ~ "bar").toString == "http://example.org/foo/bar");
	// Still don't add one even if you're appending with a slash.
	assert((url ~ "/bar").toString == "http://example.org/foo/bar");
	url ~= "/bar";
	assert(url.toString == "http://example.org/foo/bar");

	// No path.
	url = parseURL("http://example.org");
	assert((url ~ "bar").toString == "http://example.org/bar");
	assert((url ~ "/bar").toString == "http://example.org/bar");
	url ~= "bar";
	assert(url.toString == "http://example.org/bar");

	// Path is just a slash.
	url = parseURL("http://example.org/");
	assert((url ~ "bar").toString == "http://example.org/bar");
	assert((url ~ "/bar").toString == "http://example.org/bar");
	url ~= "bar";
	assert(url.toString == "http://example.org/bar", url.toString);
}

/**
	* Parse the input string as a URL.
	*
	* Throws:
	*   URLException if the string was in an incorrect format.
	*/
URL parseURL(string value) {
	URL url;
	if (tryParseURL(value, url)) {
		return url;
	}
	throw new URLException("failed to parse URL " ~ value);
}

///
unittest {
	{
		// Infer scheme
		auto u1 = parseURL("example.org");
		assert(u1.scheme == "http");
		assert(u1.host == "example.org");
		assert(u1.path == "");
		assert(u1.port == 80);
		assert(u1.providedPort == 0);
		assert(u1.fragment == "");
	}
	{
		// Simple host and scheme
		auto u1 = parseURL("https://example.org");
		assert(u1.scheme == "https");
		assert(u1.host == "example.org");
		assert(u1.path == "");
		assert(u1.port == 443);
		assert(u1.providedPort == 0);
	}
	{
		// With path
		auto u1 = parseURL("https://example.org/foo/bar");
		assert(u1.scheme == "https");
		assert(u1.host == "example.org");
		assert(u1.path == "/foo/bar", "expected /foo/bar but got " ~ u1.path);
		assert(u1.port == 443);
		assert(u1.providedPort == 0);
	}
	{
		// With explicit port
		auto u1 = parseURL("https://example.org:1021/foo/bar");
		assert(u1.scheme == "https");
		assert(u1.host == "example.org");
		assert(u1.path == "/foo/bar", "expected /foo/bar but got " ~ u1.path);
		assert(u1.port == 1021);
		assert(u1.providedPort == 1021);
	}
	{
		// With user
		auto u1 = parseURL("https://bob:secret@example.org/foo/bar");
		assert(u1.scheme == "https");
		assert(u1.host == "example.org");
		assert(u1.path == "/foo/bar");
		assert(u1.port == 443);
		assert(u1.user == "bob");
		assert(u1.pass == "secret");
	}
	{
		// With user, URL-encoded
		auto u1 = parseURL("https://bob%21:secret%21%3F@example.org/foo/bar");
		assert(u1.scheme == "https");
		assert(u1.host == "example.org");
		assert(u1.path == "/foo/bar");
		assert(u1.port == 443);
		assert(u1.user == "bob!");
		assert(u1.pass == "secret!?");
	}
	{
		// With user and port and path
		auto u1 = parseURL("https://bob:secret@example.org:2210/foo/bar");
		assert(u1.scheme == "https");
		assert(u1.host == "example.org");
		assert(u1.path == "/foo/bar");
		assert(u1.port == 2210);
		assert(u1.user == "bob");
		assert(u1.pass == "secret");
		assert(u1.fragment == "");
	}
	{
		// With query string
		auto u1 = parseURL("https://example.org/?login=true");
		assert(u1.scheme == "https");
		assert(u1.host == "example.org");
		assert(u1.path == "/", "expected path: / actual path: " ~ u1.path);
		assert(u1.query["login"] == "true");
		assert(u1.fragment == "");
	}
	{
		// With query string and fragment
		auto u1 = parseURL("https://example.org/?login=true#justkidding");
		assert(u1.scheme == "https");
		assert(u1.host == "example.org");
		assert(u1.path == "/", "expected path: / actual path: " ~ u1.path);
		assert(u1.query["login"] == "true");
		assert(u1.fragment == "justkidding");
	}
	{
		// With URL-encoded values
		auto u1 = parseURL("https://example.org/%E2%98%83?%E2%9D%84=%3D#%5E");
		assert(u1.scheme == "https");
		assert(u1.host == "example.org");
		assert(u1.path == "/☃", "expected path: /☃ actual path: " ~ u1.path);
		assert(u1.query["❄"] == "=");
		assert(u1.fragment == "^");
	}
}

unittest {
	assert(parseURL("http://example.org").port == 80);
	assert(parseURL("http://example.org:5326").port == 5326);

	auto url = parseURL("redis://admin:password@redisbox.local:2201/path?query=value#fragment");
	assert(url.scheme == "redis");
	assert(url.user == "admin");
	assert(url.pass == "password");

	assert(parseURL("example.org").toString == "http://example.org/");
	assert(parseURL("http://example.org:80").toString == "http://example.org/");

	assert(parseURL("localhost:8070").toString == "http://localhost:8070/");
}

/**
	* Percent-encode a string.
	*
	* URL components cannot contain non-ASCII characters, and there are very few characters that are
	* safe to include as URL components. Domain names using Unicode values use Punycode. For
	* everything else, there is percent encoding.
	*/
string percentEncode(string raw) {
	// We *must* encode these characters: :/?#[]@!$&'()*+,;="
	// We *can* encode any other characters.
	// We *should not* encode alpha, numeric, or -._~.
	Appender!string app;
	foreach (dchar d; raw) {
		if (('a' <= d && 'z' >= d) ||
				('A' <= d && 'Z' >= d) ||
				('0' <= d && '9' >= d) ||
				d == '-' || d == '.' || d == '_' || d == '~') {
			app ~= d;
			continue;
		}
		// Something simple like a space character? Still in 7-bit ASCII?
		// Then we get a single-character string out of it and just encode
		// that one bit.
		// Something not in 7-bit ASCII? Then we percent-encode each octet
		// in the UTF-8 encoding (and hope the server understands UTF-8).
		char[] c;
		encode(c, d);
		auto bytes = cast(ubyte[])c;
		foreach (b; bytes) {
			app ~= format("%%%02X", b);
		}
	}
	return cast(string)app.data;
}

///
unittest {
	assert(percentEncode("IDontNeedNoPercentEncoding") == "IDontNeedNoPercentEncoding");
	assert(percentEncode("~~--..__") == "~~--..__");
	assert(percentEncode("0123456789") == "0123456789");

	string e;

	e = percentEncode("☃");
	assert(e == "%E2%98%83", "expected %E2%98%83 but got" ~ e);
}

/**
	* Percent-decode a string.
	*
	* URL components cannot contain non-ASCII characters, and there are very few characters that are
	* safe to include as URL components. Domain names using Unicode values use Punycode. For
	* everything else, there is percent encoding.
	*
	* This explicitly ensures that the result is a valid UTF-8 string.
	*/
string percentDecode(string encoded) {
	ubyte[] raw = percentDecodeRaw(encoded);
	auto s = cast(string) raw;
	if (!s.isValid) {
		// TODO(dhasenan): 
		throw new URLException("input contains invalid UTF data");
	}
	return s;
}

///
unittest {
	assert(percentDecode("IDontNeedNoPercentDecoding") == "IDontNeedNoPercentDecoding");
	assert(percentDecode("~~--..__") == "~~--..__");
	assert(percentDecode("0123456789") == "0123456789");

	string e;

	e = percentDecode("%E2%98%83");
	assert(e == "☃", "expected a snowman but got" ~ e);
}

/**
	* Percent-decode a string into a ubyte array.
	*
	* URL components cannot contain non-ASCII characters, and there are very few characters that are
	* safe to include as URL components. Domain names using Unicode values use Punycode. For
	* everything else, there is percent encoding.
	*
	* This yields a ubyte array and will not perform validation on the output. However, an improperly
	* formatted input string will result in a URLException.
	*/
ubyte[] percentDecodeRaw(string encoded) {
	// We're dealing with possibly incorrectly encoded UTF-8. Mark it down as ubyte[] for now.
	Appender!(ubyte[]) app;
	for (int i = 0; i < encoded.length; i++) {
		if (encoded[i] != '%') {
			app ~= encoded[i];
			continue;
		}
		if (i >= encoded.length - 2) {
			throw new URLException("Invalid percent encoded value: expected two characters after " ~
					"percent symbol. Error at index " ~ i.to!string);
		}
		auto b = cast(ubyte)("0123456789ABCDEF".indexOf(encoded[i + 1]));
		auto c = cast(ubyte)("0123456789ABCDEF".indexOf(encoded[i + 2]));
		app ~= cast(ubyte)((b << 4) | c);
		i += 2;
	}
	return app.data;
}

/++
string toAscii(string unicodeHostname) {
	bool mustEncode = false;
	foreach (i, dchar d; unicodeHostname) {
		auto c = cast(uint) d;
		if (c > 0x80) {
			mustEncode = true;
			break;
		}
		if (c < 0x2C || (c >= 0x3A && c <= 40) || (c >= 0x5B && c <= 0x60) || (c >= 0x7B)) {
			throw new URLException(
					format(
						"domain name '%s' contains illegal character '%s' at position %s",
						unicodeHostname, d, i));
		}
	}
	if (!mustEncode) {
		return unicodeHostname;
	}
	auto parts = unicodeHostname.split('.');
	char[] result;
	foreach (part; parts) {
		result ~= punyEncode(part);
	}
	return cast(string)result;
}

string punyEncode(string item, string delimiter = null, string marker = null) {
	// Puny state machine initial variables.
	auto base = 36;
	auto tmin = 1;
	auto tmax = 26;
	auto skew = 38;
	auto damp = 700;
	auto initialBias = 72;
	long b = 0;

	bool needToEncode = false;
	Appender!(char[]) app;
	app ~= marker;
	foreach (dchar d; item) {
		if (d > '~') {  // Max printable ASCII. The DEL char isn't allowed in hostnames.
			needToEncode = true;
		} else {
			app ~= d;
			b++;
		}
	}
	if (!needToEncode) {
		return item;
	}
	app ~= delimiter;

	// The puny algorithm.
	// We use 64-bit arithmetic to avoid overflow issues -- unicode only defines up to 0x10FFFF,
	// and we won't be encoding gigabytes of data, but just to be safe.
	// Also we use signed values just to make things easier.
	long delta = 0;
	long bias = initialBias;
	long h = b;
	long lastIndex = 0;

	dchar digitToBasic(ulong digit) {
		if (digit < 26) {
			return 'a' + cast(dchar)digit;
		}
		return cast(dchar)('0' + (digit - 26));
	}

	ulong adapt(ulong delta, ulong numPoints, bool firstTime) {
		auto k = 0;
		delta = firstTime ? (delta / damp) : delta >> 1;
		delta += (delta / numPoints);
		for (; delta > (base - tmin) * tmax >> 1; k += base) {
			delta = (delta / (base - tmin));
		}
		return k + (base - tmin + 1) * delta / (delta + skew);
	}

	auto f = filter!(x => x >= cast(dchar)128)(item).array;
	auto uniqueChars = uniq(std.algorithm.sorting.sort(f));
	foreach (dchar n; uniqueChars) {
		foreach (dchar c; item) {
			if (c < n) {
				delta++;
			} else if (c == n) {
				auto q = delta;
				for (ulong k = 0; k < cast(ulong)uint.max; k += base) {
					auto t = k <= bias ? tmin : (k >= bias + tmax ? tmax : k - bias);
					if (q < t) {
						break;
					}
					app ~= digitToBasic(t + ((q - t) % (base - t)));
					q = (q - t) / (base - t);
				}
				app ~= digitToBasic(q);
				bias = adapt(delta, h + 1, h == b);
				h++;
			}
		}
		delta++;
	}
	return cast(string)app.data;
}

unittest {
	import std.stdio;
	auto a = "\u0644\u064A\u0647\u0645\u0627\u0628\u062A\u0643\u0644"
		~ "\u0645\u0648\u0634\u0639\u0631\u0628\u064A\u061F";
	writeln(a);
	writeln(punyEncode(a));
	assert(punyEncode(a) == "egbpdaj6bu4bxfgehfvwxn");
}

struct URL {
	Host host;
}
++/
