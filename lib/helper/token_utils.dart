import 'dart:convert';

import 'package:aad_oauth/model/token.dart';

class TokenUtils {
  static String toJsonString(Token token) {
    final data = Token.toJsonMap(token);
    return jsonEncode(data);
  }

  static Token fromJsonString(String? json){
    if(json == null) return Token();
    try{
      return Token.fromJson(jsonDecode(json));
    } catch (e) {
      return Token();
    }
  }
}