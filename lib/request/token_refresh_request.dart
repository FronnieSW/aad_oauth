import 'package:aad_oauth/model/config.dart';
import 'package:aad_oauth/model/token.dart';

class TokenRefreshRequestDetails {
  final String url;
  final Map<String, String> params;
  final Map<String, String> headers;

  TokenRefreshRequestDetails(Config config, Token token)
      : url = config.tokenUrl,
        params = {
          'client_id': token.clientId!,
          'scope': token.scope!,
          'redirect_uri': token.redirectUri!,
          'grant_type': 'refresh_token',
          'refresh_token': token.refreshToken!
        },
        headers = {
          'Accept': 'application/json',
          'Content-Type': Config.contentType,
          if (config.origin != null) 'Origin': config.origin!,
        } {
    if (config.clientSecret != null) {
      params.putIfAbsent('client_secret', () => token.clientSecret!);
    }
  }
}
