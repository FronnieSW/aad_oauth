import 'package:aad_oauth/helper/core_oauth.dart';
import 'package:aad_oauth/model/config.dart';
import 'package:aad_oauth/model/failure.dart';
import 'package:aad_oauth/model/token.dart';
import 'package:dartz/dartz.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:flutter_account_manager/flutter_account_manager.dart';

import 'package:aad_oauth/helper/token_utils.dart';

import '../request_code.dart';
import '../request_token.dart';

class MobileOAuth extends CoreOAuth {
  final FlutterAccountManager _accountManager;
  final RequestCode _requestCode;
  final RequestToken _requestToken;

  /// Instantiating MobileAadOAuth authentication.
  /// [config] Parameters according to official Microsoft Documentation.
  MobileOAuth(Config config)
      : _accountManager = FlutterAccountManager(config.amName, config.amType),
        _requestCode = RequestCode(config),
        _requestToken = RequestToken(config);

  /// Perform Azure AD login.
  ///
  /// Setting [refreshIfAvailable] to `true` will attempt to re-authenticate
  /// with the existing refresh token, if any, even though the access token may
  /// still be valid. If there's no refresh token the existing access token
  /// will be returned, as long as we deem it still valid. In the event that
  /// both access and refresh tokens are invalid, the web gui will be used.
  @override
  Future<Either<Failure, Token>> login(
      {bool refreshIfAvailable = false}) async {
    // await _removeOldTokenOnFirstLogin();
    return await _authorization(refreshIfAvailable: refreshIfAvailable);
  }

  /// Retrieve cached OAuth Access Token.
  @override
  Future<String?> getAccessToken() async =>
      TokenUtils.fromJsonString((await _accountManager.loadToken()))
          .accessToken;

  /// Retrieve cached OAuth Id Token.
  @override
  Future<String?> getIdToken() async =>
      TokenUtils.fromJsonString((await _accountManager.loadToken())).idToken;

  /// Perform Azure AD logout.
  @override
  Future<void> logout() async {
    await _accountManager.deleteToken();
    await _requestCode.clearCookies();
  }

  @override
  Future<bool> get hasCachedAccountInformation async =>
      TokenUtils.fromJsonString((await _accountManager.loadToken()))
          .accessToken !=
      null;

  /// Authorize user via refresh token or web gui if necessary.
  ///
  /// Setting [refreshIfAvailable] to [true] will attempt to re-authenticate
  /// with the existing refresh token, if any, even though the access token may
  /// still be valid. If there's no refresh token the existing access token
  /// will be returned, as long as we deem it still valid. In the event that
  /// both access and refresh tokens are invalid, the web gui will be used.
  Future<Either<Failure, Token>> _authorization(
      {bool refreshIfAvailable = false}) async {
    await _requestCode.clearCookies();

    var token = TokenUtils.fromJsonString((await _accountManager.loadToken()));

    if (!refreshIfAvailable) {
      if (token.hasValidAccessToken()) {
        return Right(token);
      }
    }

    if (token.refreshAvailable()) {
      final result =
          await _requestToken.requestRefreshToken(token);
      //If refresh token request throws an exception, we have to do
      //a fullAuthFlow.
      result.fold(
        (l) => token.accessToken = null,
        (r) => token = r,
      );
    }

    if (!token.hasValidAccessToken()) {
      final result = await _performFullAuthFlow();
      var failure;
      result.fold(
        (l) => failure = l,
        (r) => token = r,
      );
      if (failure != null) {
        return Left(failure);
      }
    }
    await _accountManager.setToken(TokenUtils.toJsonString(token));
    return Right(token);
  }

  /// Authorize user via refresh token or web gui if necessary.
  Future<Either<Failure, Token>> _performFullAuthFlow() async {
    var code = await _requestCode.requestCode();
    if (code == null) {
      return Left(AadOauthFailure(
        ErrorType.AccessDeniedOrAuthenticationCanceled,
        'Access denied or authentication canceled.',
      ));
    }
    return await _requestToken.requestToken(code);
  }

  Future<void> _removeOldTokenOnFirstLogin() async {
    var prefs = await SharedPreferences.getInstance();
    final _keyFreshInstall = 'freshInstall';
    if (!prefs.getKeys().contains(_keyFreshInstall)) {
      await logout();
      await prefs.setBool(_keyFreshInstall, false);
    }
  }
}

CoreOAuth getOAuthConfig(Config config) => MobileOAuth(config);
