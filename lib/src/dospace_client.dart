import 'dart:async';
import 'dart:convert';
import 'package:meta/meta.dart';
import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;
import 'package:xml/xml.dart' as xml;

class ClientException implements Exception {
  final int statusCode;
  final String reasonPhrase;
  final Map<String, String> responseHeaders;
  final String responseBody;
  const ClientException(this.statusCode, this.reasonPhrase,
      this.responseHeaders, this.responseBody);
  String toString() {
    return "DOException { statusCode: ${statusCode}, reasonPhrase: \"${reasonPhrase}\", responseBody: \"${responseBody}\" }";
  }
}

class Client {
  final String region;
  final String accessKey;
  final String secretKey;
  final String service;
  final String endpointUrl;

  @protected
  final http.Client httpClient;

  Client(
      {required this.region,
      required this.accessKey,
      required this.secretKey,
      required this.service,
      String? endpointUrl,
      http.Client? httpClient})
      : this.endpointUrl =
            endpointUrl ?? "https://${region}.digitaloceanspaces.com",
        this.httpClient = httpClient ?? new http.Client() {}

  Future<void> close() async {
    httpClient.close();
  }

  @protected
  Future<xml.XmlDocument> getUri(Uri uri) async {
    http.Request request = new http.Request('GET', uri);
    signRequest(request);
    http.StreamedResponse response = await httpClient.send(request);
    String body = await utf8.decodeStream(response.stream);
    if (response.statusCode != 200) {
      throw new ClientException(response.statusCode,
          response.reasonPhrase ?? "", response.headers, body);
    }
    xml.XmlDocument doc = xml.XmlDocument.parse(body);
    return doc;
  }

  String _uriEncode(String str) {
    return Uri.encodeQueryComponent(str).replaceAll('+', '%20');
  }

  String _trimAll(String str) {
    String res = str.trim();
    int len;
    do {
      len = res.length;
      res = res.replaceAll('  ', ' ');
    } while (res.length != len);
    return res;
  }

  @protected
  String? signRequest(http.BaseRequest request,
      {Digest? contentSha256, bool preSignedUrl = false, int expires = 86400}) {
    if (preSignedUrl) {
      // Use existing SigV4 for pre-signed URLs as it's more secure
      return _signRequestV4(request,
          contentSha256: contentSha256, preSignedUrl: true, expires: expires);
    }

    // SigV2 Implementation
    DateTime date = new DateTime.now().toUtc();
    String dateRfc822 = _formatDateRfc822(date);

    // Build string to sign
    StringBuffer stringToSign = StringBuffer();
    stringToSign.write(request.method);
    stringToSign.write('\n');

    // Add content MD5 if available
    stringToSign.write('\n');

    // Add content type if available
    String? contentType = request.headers['content-type'];
    stringToSign.write(contentType ?? '');
    stringToSign.write('\n');

    // Add date
    stringToSign.write(dateRfc822);
    stringToSign.write('\n');

    // Add canonicalized AMZ headers
    Map<String, String> amzHeaders = _getAmzHeaders(request.headers);
    if (amzHeaders.isNotEmpty) {
      List<String> sortedAmzHeaders = amzHeaders.keys.toList()..sort();
      for (String key in sortedAmzHeaders) {
        stringToSign.write('$key:${amzHeaders[key]}\n');
      }
    }

    // Add canonicalized resource
    stringToSign.write(request.url.path);

    // Add sub-resources if present
    String canonicalizedQuery = _getCanonicalizedQuery(request.url.queryParameters);
    if (canonicalizedQuery.isNotEmpty) {
      stringToSign.write('?$canonicalizedQuery');
    }

    // Calculate signature
    List<int> key = utf8.encode(secretKey);
    List<int> message = utf8.encode(stringToSign.toString());
    Digest hmac = new Hmac(sha1, key).convert(message);
    String signature = base64.encode(hmac.bytes);

    // Set headers
    request.headers['Date'] = dateRfc822;
    request.headers['Authorization'] = 'AWS $accessKey:$signature';

    return null;
  }

// Helper method to format date in RFC 822 format
  String _formatDateRfc822(DateTime date) {
    final List<String> months = [
      'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
      'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'
    ];
    final List<String> days = [
      'Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'
    ];

    String pad2(int n) => n.toString().padLeft(2, '0');

    return '${days[date.weekday % 7]}, ${pad2(date.day)} ${months[date.month - 1]} '
        '${date.year} ${pad2(date.hour)}:${pad2(date.minute)}:${pad2(date.second)} GMT';
  }

// Helper method to get AMZ headers
  Map<String, String> _getAmzHeaders(Map<String, String> headers) {
    Map<String, String> amzHeaders = {};
    headers.forEach((key, value) {
      String lowerKey = key.toLowerCase();
      if (lowerKey.startsWith('x-amz-')) {
        amzHeaders[lowerKey] = value;
      }
    });
    return amzHeaders;
  }

// Helper method to get canonicalized query string
  String _getCanonicalizedQuery(Map<String, String> params) {
    if (params.isEmpty) return '';

    List<String> subResources = [
      'acl', 'lifecycle', 'location', 'logging', 'notification',
      'partNumber', 'policy', 'requestPayment', 'torrent',
      'uploadId', 'uploads', 'versionId', 'versioning',
      'versions', 'website'
    ];

    List<String> queryParts = [];
    params.forEach((key, value) {
      if (subResources.contains(key.toLowerCase())) {
        if (value.isEmpty) {
          queryParts.add(key);
        } else {
          queryParts.add('$key=$value');
        }
      }
    });

    queryParts.sort();
    return queryParts.join('&');
  }

  @protected
  String? _signRequestV4(http.BaseRequest request,
      {Digest? contentSha256, bool preSignedUrl = false, int expires = 86400}) {
    // Build canonical request
    String httpMethod = request.method;
    String canonicalURI = request.url.path;
    String host = request.url.host;
    // String service = 's3';

    DateTime date = new DateTime.now().toUtc();
    String dateIso8601 = date.toIso8601String();
    dateIso8601 = dateIso8601
            .substring(0, dateIso8601.indexOf('.'))
            .replaceAll(':', '')
            .replaceAll('-', '') +
        'Z';
    String dateYYYYMMDD = date.year.toString().padLeft(4, '0') +
        date.month.toString().padLeft(2, '0') +
        date.day.toString().padLeft(2, '0');

    // dateIso8601 = "20130524T000000Z";
    // dateYYYYMMDD = "20130524";
    // hashedPayload = null;
    String hashedPayloadStr =
        contentSha256 == null ? 'UNSIGNED-PAYLOAD' : '$contentSha256';

    String credential =
        '${accessKey}/${dateYYYYMMDD}/${region}/${service}/aws4_request';

    // Build canonical headers string
    Map<String, String> headers = new Map<String, String>();
    if (!preSignedUrl) {
      request.headers['x-amz-date'] = dateIso8601; // Set date in header
      if (contentSha256 != null) {
        request.headers['x-amz-content-sha256'] =
            hashedPayloadStr; // Set payload hash in header
      }
      request.headers.keys.forEach((String name) =>
          (headers[name.toLowerCase()] = request.headers[name] ?? ""));
    }
    headers['host'] = host; // Host is a builtin header
    List<String> headerNames = headers.keys.toList()..sort();
    String canonicalHeaders = headerNames
        .map((s) => '${s}:${_trimAll(headers[s] ?? "")}' + '\n')
        .join();

    String signedHeaders = headerNames.join(';');

    // Build canonical query string
    Map<String, String> queryParameters = new Map<String, String>()
      ..addAll(request.url.queryParameters);
    if (preSignedUrl) {
      // Add query parameters
      queryParameters['X-Amz-Algorithm'] = 'AWS4-HMAC-SHA256';
      queryParameters['X-Amz-Credential'] = credential;
      queryParameters['X-Amz-Date'] = dateIso8601;
      queryParameters['X-Amz-Expires'] = expires.toString();
      if (contentSha256 != null) {
        queryParameters['X-Amz-Content-Sha256'] = hashedPayloadStr;
      }
      queryParameters['X-Amz-SignedHeaders'] = signedHeaders;
    }
    List<String> queryKeys = queryParameters.keys.toList()..sort();
    String canonicalQueryString = queryKeys
        .map((s) => '${_uriEncode(s)}=${_uriEncode(queryParameters[s] ?? "")}')
        .join('&');

    if (preSignedUrl) {
      // TODO: Specific payload upload with pre-signed URL not supported on DigitalOcean?
      hashedPayloadStr = 'UNSIGNED-PAYLOAD';
    }

    // Sign headers
    String canonicalRequest =
        '${httpMethod}\n${canonicalURI}\n${canonicalQueryString}\n${canonicalHeaders}\n${signedHeaders}\n$hashedPayloadStr';
    // print('\n>>>>>> canonical request \n' + canonicalRequest + '\n<<<<<<\n');

    Digest canonicalRequestHash = sha256.convert(utf8.encode(
        canonicalRequest)); //_hmacSha256.convert(utf8.encode(canonicalRequest));

    String stringToSign =
        'AWS4-HMAC-SHA256\n${dateIso8601}\n${dateYYYYMMDD}/${region}/${service}/aws4_request\n$canonicalRequestHash';
    // print('\n>>>>>> string to sign \n' + stringToSign + '\n<<<<<<\n');

    Digest dateKey = new Hmac(sha256, utf8.encode("AWS4${secretKey}"))
        .convert(utf8.encode(dateYYYYMMDD));
    Digest dateRegionKey =
        new Hmac(sha256, dateKey.bytes).convert(utf8.encode(region));
    Digest dateRegionServiceKey =
        new Hmac(sha256, dateRegionKey.bytes).convert(utf8.encode(service));
    Digest signingKey = new Hmac(sha256, dateRegionServiceKey.bytes)
        .convert(utf8.encode("aws4_request"));

    Digest signature =
        new Hmac(sha256, signingKey.bytes).convert(utf8.encode(stringToSign));

    // Set signature in header
    request.headers['Authorization'] =
        'AWS4-HMAC-SHA256 Credential=${credential}, SignedHeaders=${signedHeaders}, Signature=$signature';

    if (preSignedUrl) {
      queryParameters['X-Amz-Signature'] = '$signature';
      return request.url.replace(queryParameters: queryParameters).toString();
    } else {
      return null;
    }
  }
}
