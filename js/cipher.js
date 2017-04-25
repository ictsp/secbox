/**
 * 暗号化・復号化を行うためのライブラリ。 暗号化・復号化にはCryptoJSライブラリ
 * (https://code.google.com/p/crypto-js)を使用する。 暗号方式はAES-256を採用。
 *
 * 【関数群】
 *
 * GetAes256Passphrase AES-256用のパスフレーズを作成する関数 Aes256Encrypt CryptoJSを使って暗号化する関数
 * Aes256Decrypt CryptoJSを使って復号する関数 Encrypt0 暗号化関数（セキュリティレベル０用） Encrypt1
 * 暗号化関数（セキュリティレベル１用） Encrypt2 暗号化関数（セキュリティレベル２用） Decrypt0 復号化関数（セキュリティレベル０用）
 * Decrypt1 復号化関数（セキュリティレベル１用） Decrypt2 復号化関数（セキュリティレベル２用） GetPassphraseItem
 * フォームからGetAes256Passphrase関数で既定の長さに変更したパスフレーズを取得する関数 DecryptItem
 * セキュリティレベルとパスフレーズの入力状況によりフォーム項目を復号する関数 PrintStackTrace
 * 例外オブジェクトからスタックトレースを出力する関数
 *
 *
 * 【参考サイト】
 *
 * アプリ作家見習いメモ http://dokuwiki.eniblo.org/doku.php/javascript/library/crypto_js
 * 自己言及のパラドックス http://sct9.blog85.fc2.com/blog-entry-62.html
 * JavaScriptで暗号化した文字列をRubyで復号化してみた
 * http://qiita.com/shigekid/items/60d3387de6a804bc38b9 DEV TIPS
 * http://www.hiihah.info/index.php?JavaScript%EF%BC%9ACryptoJS%E3%82%92%E4%BD%BF%E3%81%A3%E3%81%A6%E7%94%BB%E5%83%8F%E3%82%92%E6%9A%97%E5%8F%B7%E5%8C%96%E3%83%BB%E5%BE%A9%E5%8F%B7%E3%81%99%E3%82%8B
 *
 * @author Hirotomo Okazawa
 * @version 1.0
 */

var CIPHER = {
	'OK' : 'OK',
	'NG' : 'NG',
	'UNDEF' : 'undefined',
	'UNMATCH' : 'UNMATCH',
	'LEVEL0' : '0',
	'LEVEL1' : '1',
	'LEVEL2' : '2'
};
/**
 * AES-256用のパスフレーズを作成する関数
 *
 * @param passphrase
 *            暗号化するための、パスフレーズ
 * @return passphraseを32Byteに変更した文字列。 passphrase>32Byteの場合、先頭32Byteを取り出す。
 *         passphrase<32Byteの場合、32Byteになるまでpassphraseを繰り返し連結する。
 * @note 全角が混じると32Byte以上になってしまうがCryptoJSでうまく処理してくれるので気にしない
 */
function GetAes256Passphrase(key) {

	// 返却する文字列を空にする
	var secretPassphrase = "";

	// 返却する文字列が32文字未満の間繰り返す
	while (secretPassphrase.length < 32) {
		// 返却する文字列の後ろにkeyを連結する。
		secretPassphrase = secretPassphrase + key;
	}

	// console.log('secretPassphrase : %s', secretPassphrase.substring(0, 32));

	// 32文字以上になった文字列の先頭32文字を切り取って返却する。
	return secretPassphrase.substring(0, 32);
}

/**
 * CryptoJSを使って暗号化する関数
 *
 * @param plain
 *            暗号化したい元の文字列
 * @param passphrase
 *            パスフレーズ
 * @return 暗号化した文字列
 */
function Aes256Encrypt(plain, passphraseName, passphrase) {

	// パラメタチェック
	if (!plain) {
		// 暗号化したい元の文字列が指定されていない場合は空文字列を返却する
		return {
			rc : CIPHER.OK,
			encryptedValue : '',
			message : ''
		};
	}

	// パラメタチェック
	if (!passphrase) {
		// パスフレーズが指定されていない場合はエラーにする

		// エラーメッセージを作成する
		var message = passphraseName + "が指定されていません";

		console.log('暗号化失敗 理由: %s', message);

		return {
			rc : CIPHER.NG,
			encryptedValue : null,
			message : message
		};
	}

	// 暗号化したいオブジェクトを文字列に変換する（念のため）
	var source = plain.toString();

	// 暗号化
	var encrypted;
	try {
		// AES-256で暗号化する
		encrypted = CryptoJS.AES.encrypt(source, passphrase);
		if (!encrypted) {
			// 暗号化失敗

			// エラーメッセージを作成する
			var message = "暗号化失敗";

			console.log('暗号化失敗 理由: %s', message);

			return {
				rc : CIPHER.NG,
				encryptedValue : null,
				message : message
			};
		}
	} catch (e) {
		// エラーメッセージを作成する
		var message = e.message;
		console
				.log(
						'CryptoJS.AES.encryptで例外発生 : %s source=[%s] passphraseName=[%s] passphrase=[%s]',
						message, source, passphraseName, passphrase);

		// エラーの詳細出力
		PrintStackTrace(e);

		console.log('暗号化失敗 理由: %s', message);

		return {
			rc : CIPHER.NG,
			encryptedValue : null,
			message : message
		};
	}

	// 暗号化された文字列を取り出す
	var encryptedString = encrypted.toString();

	// デバッグログ
	console.log('Aes256Encrypt : %s --> %s', source, encryptedString);

	// 暗号化された文字列を復号して一致するか確認する
	var test = Aes256Decrypt(encryptedString, passphraseName, passphrase);
	if (test.rc !== CIPHER.OK || test.decryptedValue !== source) {
		// testとsourceが一致しない場合はエラーとする

		// エラーメッセージを作成する
		var message = "復号テストエラー（暗号化前の文字列と復号した結果が一致しない）";

		console.log('暗号化失敗 理由: %s', message);

		return {
			rc : CIPHER.NG,
			encryptedValue : null,
			message : message
		};
	}

	// 暗号化した文字列を返却する
	return {
		rc : CIPHER.OK,
		encryptedValue : encryptedString,
		message : message
	};
}

/**
 * CryptoJSを使って復号する関数
 *
 * @param encrypted
 *            暗号化された文字列
 * @param passphrase
 *            パスフレーズ
 * @param errorAlert
 *            エラー発生時にメッセージダイアログを表示するか否かを指定する。 true:エラー発生時にメッセージダイアログを表示する
 *            false:エラー発生時にメッセージダイアログを表示しない
 * @return 復号した文字列
 */
function Aes256Decrypt(encrypted, passphraseName, passphrase) {

	// パラメタチェック
	if (!encrypted) {
		// 暗号化された文字列が指定されていない場合は空文字列を返却する
		return {
			rc : CIPHER.OK,
			decryptedValue : '',
			message : ''
		};
	}

	// パラメタチェック
	if (!passphrase) {
		// パスフレーズが指定されていない場合はエラーにする

		// エラーメッセージを作成する
		var message = passphraseName + "が指定されていません";

		console.log('復号化失敗 理由: %s', message);

		return {
			rc : CIPHER.NG,
			decryptedValue : null,
			message : message
		};
	}

	// 復号
	var decrypted;
	try {
		// 暗号化された文字列(encrypted)をパスフレーズ(passphrase)を使ってAES-256で復号する
		decrypted = CryptoJS.AES.decrypt(encrypted, passphrase);
		// console.log(decrypted);
		// エラー判定（パスフレーズが間違っているときは空文字列が返る）
		if (!decrypted || !(decrypted.toString())) {
			var message = passphraseName + "が違うか暗号文字列が壊れています";
			console
					.log(
							'復号失敗 : %s encrypted=[%s] passphraseName=[%s] passphrase=[%s]',
							message, encrypted, passphraseName, passphrase);

			console.log('復号化失敗 理由: %s', message);

			return {
				rc : CIPHER.NG,
				decryptedValue : null,
				message : message
			};
		}
	} catch (e) {
		// エラーメッセージを作成する
		var message = e.message;
		console
				.log(
						'CryptoJS.AES.decryptで例外発生 : %s encrypted=[%s] passphraseName=[%s] passphrase=[%s]',
						message, encrypted, passphraseName, passphrase);

		// エラーの詳細出力
		PrintStackTrace(e);

		console.log('復号化失敗 理由: %s', message);

		return {
			rc : CIPHER.NG,
			decryptedValue : null,
			message : message
		};
	}

	// 復号した文字列を取り出す
	var plain;
	try {
		plain = decrypted.toString(CryptoJS.enc.Utf8);
	} catch (e) {
		// エラーメッセージを作成する
		var message = e.message;
		console.log('decrypted.toString(CryptoJS.enc.Utf8)で例外発生 : %s', message);

		// エラーの詳細出力
		PrintStackTrace(e);

		console.log('復号化失敗 理由: %s', message);

		return {
			rc : CIPHER.NG,
			decryptedValue : null,
			message : message
		};
	}

	console.log('Aes256Decrypt : %s --> %s', encrypted.toString(), plain);

	// 復号した文字列を返却する
	return {
		rc : CIPHER.OK,
		decryptedValue : plain,
		message : ""
	};

}

/**
 * 暗号化関数（セキュリティレベル０用）
 *
 * @param plain
 *            暗号化したい元の文字列
 * @return セキュリティレベル０で暗号化された文字列
 * @note 基本的には元の文字列をそのまま返すだけ
 */
function Encrypt0(plain) {

	// パラメタチェック
	if (!plain) {
		// 暗号化したい元の文字列が指定されていない場合は空文字列を返却する
		return {
			rc : CIPHER.OK,
			level : CIPHER.LEVEL0,
			encryptedValue : "",
			message : ""
		};
	}

	// 暗号化したい元の文字列をUTF-8に変換して返却する
	// return CryptoJS.enc.Utf8.parse(plain);
	return {
		rc : CIPHER.OK,
		level : CIPHER.LEVEL0,
		encryptedValue : plain.toString(),
		message : ""
	};
}

/**
 * 暗号化関数（セキュリティレベル１用）
 *
 * @param plain
 *            暗号化したい元の文字列
 * @param passphrase1
 *            パスフレーズ１
 * @return セキュリティレベル１の暗号結果
 */
function Encrypt1(plain, passphrase1name, passphrase1) {

	// パラメタチェック
	if (!plain) {
		// 暗号化したい元の文字列が指定されていない場合は空文字列を返却する
		return {
			rc : CIPHER.OK,
			level : CIPHER.LEVEL1,
			encryptedValue : "",
			message : ""
		};
	}

	// パラメタチェック
	if (!passphrase1) {
		// パスフレーズ１が指定されていない場合はエラーにする

		// エラーメッセージを作成する
		var message = passphrase1name + "が指定されていません";

		console.log('暗号化失敗 理由: %s', message);

		return {
			rc : CIPHER.NG,
			level : CIPHER.LEVEL1,
			encryptedValue : null,
			message : message
		};

	}

	// パスフレーズ１で暗号化
	var encrypted1;
	try {
		// AES-256で暗号化する
		encrypted1 = Aes256Encrypt(plain, passphrase1name, passphrase1);
		// 処理結果確認
		if (encrypted1.rc !== CIPHER.OK) {
			console.log('暗号化失敗 理由: %s', encrypted1.message);
			return {
				rc : CIPHER.NG,
				level : CIPHER.LEVEL1,
				encryptedValue : null,
				message : encrypted1.message
			};
		}
	} catch (e) {
		// エラーメッセージを作成する
		var message = e.message;
		console
				.log(
						'Aes256Encryptで例外発生 : %s plain=[%s] passphrase1name=[%s] passphrase1=[%s]',
						message, plain, passphrase1name, passphrase1);

		return {
			rc : CIPHER.NG,
			level : CIPHER.LEVEL1,
			encryptedValue : null,
			message : message
		};
	}

	// セキュリティレベル０で暗号化する
	var encrypted;
	try {
		encrypted = Encrypt0(encrypted1.encryptedValue);
		// 処理結果確認
		if (encrypted.rc !== CIPHER.OK) {
			console.log('暗号化失敗 理由: %s', encrypted.message);
			return {
				rc : CIPHER.NG,
				level : CIPHER.LEVEL1,
				encryptedValue : null,
				message : encrypted.message
			};
		}
	} catch (e) {
		// エラーメッセージを作成する
		var message = e.message;
		console.log('Encrypt0で例外発生 : %s passphrase1name=[%s] encrypted1=[%s]',
				message, passphrase1name, encrypted1);

		return {
			rc : CIPHER.NG,
			level : CIPHER.LEVEL1,
			encryptedValue : null,
			message : message
		};
	}

	// 暗号化した文字列を返却する
	return {
		rc : CIPHER.OK,
		level : CIPHER.LEVEL1,
		encryptedValue : encrypted.encryptedValue,
		message : ""
	};

}

/**
 * 暗号化関数（セキュリティレベル２用）
 *
 * @param plain
 *            暗号化したい元の文字列
 * @param passphrase1
 *            パスフレーズ１
 * @param passphrase2
 *            パスフレーズ２
 * @return セキュリティレベル２の暗号結果
 */
function Encrypt2(plain, passphrase1name, passphrase1, passphrase2name,
		passphrase2) {

	// パラメタチェック
	if (!plain) {
		// 暗号化したい元の文字列が指定されていない場合は空文字列を返却する
		return {
			rc : CIPHER.OK,
			level : CIPHER.LEVEL2,
			encryptedValue : "",
			message : ""
		};
	}

	// パラメタチェック
	if (!passphrase1) {
		// パスフレーズ１が指定されていない場合はエラーにする

		// エラーメッセージを作成する
		var message = passphrase1name + "が指定されていません";

		return {
			rc : CIPHER.NG,
			level : CIPHER.LEVEL2,
			encryptedValue : null,
			message : message
		};

	}

	// パラメタチェック
	if (!passphrase2) {
		// パスフレーズ２が指定されていない場合はエラーにする

		// エラーメッセージを作成する
		var message = passphrase2name + "が指定されていません";

		return {
			rc : CIPHER.NG,
			level : CIPHER.LEVEL2,
			encryptedValue : null,
			message : message
		};

	}

	// パスフレーズ２で暗号化する
	var encrypted2;
	try {
		// AES-256で暗号化する
		encrypted2 = Aes256Encrypt(plain, passphrase2name, passphrase2);
		// 処理結果確認
		if (encrypted2.rc !== CIPHER.OK) {
			console.log('暗号化失敗 理由: %s', encrypted2.message);
			return {
				rc : CIPHER.NG,
				level : CIPHER.LEVEL2,
				encryptedValue : null,
				message : encrypted2.message
			};
		}
	} catch (e) {
		// エラーメッセージを作成する
		var message = e.message;
		console
				.log(
						'Aes256Encryptで例外発生 : %s plain=[%s] passphrase2name=[%s] passphrase2=[%s]',
						message, plain, passphrase2name, passphrase2);

		return {
			rc : CIPHER.NG,
			level : CIPHER.LEVEL2,
			encryptedValue : null,
			message : message
		};

	}

	// パスフレーズ２で暗号化した文字列を更にパスフレーズ１で暗号化する。
	var encrypted;
	try {
		encrypted = Encrypt1(encrypted2.encryptedValue, passphrase1name,
				passphrase1);
		// 処理結果確認
		if (encrypted.rc !== CIPHER.OK) {
			console.log('暗号化失敗 理由: %s', encrypted.message);
			return {
				rc : CIPHER.NG,
				level : CIPHER.LEVEL2,
				encryptedValue : null,
				message : encrypted.message
			};
		}
	} catch (e) {
		// エラーメッセージを作成する
		var message = e.message;
		console
				.log(
						'Encrypt1で例外発生 : %s encrypted2=[%s] passphrase1name=[%s] passphrase1=[%s]',
						message, encrypted2, passphrase1name, passphrase1);

		return {
			rc : CIPHER.NG,
			level : CIPHER.LEVEL2,
			encryptedValue : null,
			message : message
		};

	}

	// 暗号化した文字列を返却する
	return encrypted;
}

/**
 * 復号化関数（セキュリティレベル０用）
 *
 * @param encrypted0
 *            セキュリティレベル０で暗号化された文字列
 * @param errorAlert
 *            エラー発生時にメッセージダイアログを表示するか否かを指定する。 true:エラー発生時にメッセージダイアログを表示する
 *            false:エラー発生時にメッセージダイアログを表示しない
 * @return 復号した文字列
 * @note encrypted0のNULLチェックが主な目的で、実質的には元の文字列をそのまま返す
 */
function Decrypt0(encrypted) {

	// パラメタチェック
	if (!encrypted) {
		// セキュリティレベル０で暗号化された文字列が指定されていない場合は空文字列を返却する
		return {
			rc : CIPHER.OK,
			level : CIPHER.LEVEL0,
			decryptedValue : "",
			message : ""
		};
	}

	// 渡された文字列を返却用文字列に設定する。 ※無駄な処理ですが意味が分かり易さを優先して・・・
	var plain = encrypted;

	console.log('decryptedValue --> %s', plain);

	// 復号した文字列を返却する
	return {
		rc : CIPHER.OK,
		level : CIPHER.LEVEL0,
		decryptedValue : plain,
		message : ""
	};
}

/**
 * 復号化関数（セキュリティレベル１用）
 *
 * @param encrypted1
 *            セキュリティレベル１で暗号化された文字列
 * @param passphrase1
 *            パスフレーズ１
 * @param errorAlert
 *            エラー発生時にメッセージダイアログを表示するか否かを指定する。 true:エラー発生時にメッセージダイアログを表示する
 *            false:エラー発生時にメッセージダイアログを表示しない
 * @return 復号した文字列
 */
function Decrypt1(encrypted, passphrase1name, passphrase1) {

	// パラメタチェック
	if (!encrypted) {
		// セキュリティレベル１で暗号化された文字列が指定されていない場合は空文字列を返却する
		return {
			rc : CIPHER.OK,
			level : CIPHER.LEVEL1,
			decryptedValue : "",
			message : ""
		};
	}

	// パラメタチェック
	if (!passphrase1) {
		// パスフレーズ１が指定されていない場合はエラーにする

		// エラーメッセージを作成する
		var message = passphrase1name + "が指定されていません";

		console.log('復号化失敗 理由: %s', message);

		return {
			rc : CIPHER.NG,
			level : CIPHER.LEVEL1,
			decryptedValue : null,
			message : message
		};
	}

	// セキュリティレベル０で復号する。 → パスフレーズ１で暗号化された文字列に復号される
	var encrypted0;
	try {
		// 暗号化された文字列(encrypted0)を復号する
		encrypted0 = Decrypt0(encrypted);

		console.log('rc --> %s', encrypted0.rc);
		console.log('level --> %s', encrypted0.level);
		console.log('decryptedValue --> %s', encrypted0.decryptedValue);
		console.log('message --> %s', encrypted0.message);

		// 処理結果確認
		if (encrypted0.rc !== CIPHER.OK) {
			console.log('復号化失敗 理由: %s', encrypted0.message);
			return {
				rc : CIPHER.NG,
				level : CIPHER.LEVEL1,
				decryptedValue : null,
				message : encrypted0.message
			};
		}
	} catch (e) {
		// エラーメッセージを作成する
		var message = passphrase1name + "が違うか暗号化された文字列が壊れています";
		console.log('Decrypt0で例外発生 : %s encrypted1=[%s]', message, encrypted);

		return {
			rc : CIPHER.NG,
			level : CIPHER.LEVEL1,
			decryptedValue : null,
			message : message
		};
	}

	console.log('rc --> %s', encrypted0.rc);
	console.log('level --> %s', encrypted0.level);
	console.log('decryptedValue --> %s', encrypted0.decryptedValue);
	console.log('message --> %s', encrypted0.message);

	// パスフレーズ１で復号する。 → 元の文字列に復号される
	var plain;
	try {
		// 暗号化された文字列(encrypted)をパスフレーズ(passphrase1)を使って復号する
		plain = Aes256Decrypt(encrypted0.decryptedValue, passphrase1name,
				passphrase1);

		console.log('rc --> %s', plain.rc);
		console.log('level --> %s', plain.level);
		console.log('decryptedValue --> %s', plain.decryptedValue);
		console.log('message --> %s', plain.message);

		// 処理結果確認
		if (plain.rc !== CIPHER.OK) {
			console.log('復号化失敗 理由: %s', plain.message);
			return {
				rc : CIPHER.NG,
				level : CIPHER.LEVEL1,
				decryptedValue : null,
				message : plain.message
			};
		}
	} catch (e) {
		// エラーメッセージを作成する
		var message = passphrase1name + "が違うか暗号化された文字列が壊れています";
		console
				.log(
						'Aes256Decryptで例外発生 : %s encrypted1=[%s] passphrase1name=[%s] passphrase1=[%s]',
						message, encrypted0.decryptedValue, passphrase1name,
						passphrase1);

		return {
			rc : CIPHER.NG,
			level : CIPHER.LEVEL1,
			decryptedValue : null,
			message : message
		};
	}

	// 復号した文字列を返却する
	return {
		rc : CIPHER.OK,
		level : CIPHER.LEVEL1,
		decryptedValue : plain.decryptedValue,
		message : ""
	};
}

/**
 * 復号化関数（セキュリティレベル２用）
 *
 * @param encrypted2
 *            セキュリティレベル２で暗号化された文字列
 * @param passphrase1
 *            パスフレーズ１
 * @param passphrase2
 *            パスフレーズ２
 * @param errorAlert
 *            エラー発生時にメッセージダイアログを表示するか否かを指定する。 true:エラー発生時にメッセージダイアログを表示する
 *            false:エラー発生時にメッセージダイアログを表示しない
 * @return 復号した文字列
 */
function Decrypt2(encrypted, passphrase1name, passphrase1, passphrase2name,
		passphrase2) {

	console
			.log(
					"Decrypt2（encrypted=%s, passphrase1name=%s, passphrase1=%s, passphrase1name=%s, passphrase2=%s)",
					encrypted, passphrase1name, passphrase1, passphrase2name,
					passphrase2);

	// パラメタチェック
	if (!encrypted) {
		// セキュリティレベル２で暗号化された文字列が指定されていない場合は空文字列を返却する
		return {
			rc : CIPHER.OK,
			level : CIPHER.LEVEL2,
			decryptedValue : "",
			message : ""
		};
	}

	// パラメタチェック
	if (!passphrase1) {
		// パスフレーズ１が指定されていない場合はエラーにする

		// エラーメッセージを作成する
		var message = "パスフレーズ１が指定されていません";

		console.log('復号化失敗 理由: %s', message);

		return {
			rc : CIPHER.NG,
			level : CIPHER.LEVEL2,
			decryptedValue : null,
			message : message
		};
	}

	// パラメタチェック
	if (!passphrase2) {
		// パスフレーズ２が指定されていない場合はエラーにする

		// エラーメッセージを作成する
		var message = "パスフレーズ２が指定されていません";

		console.log('復号化失敗 理由: %s', message);

		return {
			rc : CIPHER.NG,
			level : CIPHER.LEVEL2,
			decryptedValue : null,
			message : message
		};
	}

	// パスフレーズ１で復号する → パスフレーズ２で暗号化された文字列に復号される
	var encrypted1;
	try {
		// 暗号化された文字列(encrypted2)をパスフレーズ(passphrase1)を使って復号する
		encrypted1 = Decrypt1(encrypted, passphrase1name, passphrase1);

		console.log('rc --> %s', encrypted1.rc);
		console.log('level --> %s', encrypted1.level);
		console.log('decryptedValue --> %s', encrypted1.decryptedValue);
		console.log('message --> %s', encrypted1.message);

		// 処理結果確認
		if (encrypted1.rc !== CIPHER.OK) {
			console.log('復号化失敗 理由: %s', encrypted1.message);
			return {
				rc : CIPHER.NG,
				level : CIPHER.LEVEL2,
				decryptedValue : null,
				message : encrypted1.message
			};
		}
	} catch (e) {
		// エラーメッセージを作成する
		var message = passphrase1name + "が違うか暗号化された文字列が壊れています";
		console
				.log(
						'Decrypt1で例外発生 : %s encrypted=[%s] passphrase1name=[%s] passphrase1=[%s]',
						message, encrypted, passphrase1name, passphrase1);

		return {
			rc : CIPHER.NG,
			level : CIPHER.LEVEL2,
			decryptedValue : null,
			message : message
		};
	}

	console.log('rc --> %s', encrypted1.rc);
	console.log('level --> %s', encrypted1.level);
	console.log('decryptedValue --> %s', encrypted1.decryptedValue);
	console.log('message --> %s', encrypted1.message);

	// パスフレーズ２で復号する → 元の文字列に復号される
	var plain;
	try {
		// 暗号化された文字列(encrypted)をパスフレーズ(passphrase2)を使って復号する
		/*
		 * console.log('パスフレーズ２で復号開始 : encrypted=[%s] passphrase2=[%s]',
		 * encrypted, passphrase2);
		 */
		plain = Aes256Decrypt(encrypted1.decryptedValue, passphrase2name,
				passphrase2);

		console.log('rc --> %s', plain.rc);
		console.log('level --> %s', plain.level);
		console.log('decryptedValue --> %s', plain.decryptedValue);
		console.log('message --> %s', plain.message);

		// 処理結果確認
		if (!plain || plain.rc !== CIPHER.OK) {
			console.log('復号化失敗 理由: %s', plain.message);
			return {
				rc : CIPHER.NG,
				level : CIPHER.LEVEL2,
				decryptedValue : null,
				message : plain.message
			};
		}
	} catch (e) {
		// エラーメッセージを作成する
		var message = passphrase2name + "が違うか暗号化された文字列が壊れています";
		console
				.log(
						'Aes256Decrypt : %s encrypted=[%s] passphrase2name=[%s] passphrase2=[%s]',
						message, encrypted1.decryptedValue, passphrase2name,
						passphrase2);

		return {
			rc : CIPHER.NG,
			level : CIPHER.LEVEL2,
			decryptedValue : null,
			message : message
		};
	}

	// 復号した文字列を返却する
	return {
		rc : CIPHER.OK,
		level : CIPHER.LEVEL2,
		decryptedValue : plain.decryptedValue,
		message : ""
	};
}

/**
 * パスフレーズ取得関数 ※フォームからGetAes256Passphrase関数で既定の長さに変更したパスフレーズを取得する。
 * 戻り値：NULLまたはGetAes256Passphrase関数で既定の長さに変更したパスフレーズ
 */
function GetPassphraseItem(keyName, keyElementId, reKeyElementId) {

	console
			.log(
					"GetPassphraseItem(keyName=%s, keyElementId=%s, reKeyElementId=%s)",
					keyName, keyElementId, reKeyElementId);

	// パスフレーズを取得する
	var key;
	if (!keyElementId) {
		var message = keyName + "が指定されていません";
		console.log("%s", message);
		return {
			rc : CIPHER.UNDEF,
			value : null,
			message : message
		};
	}
	var keyElement = document.getElementById(keyElementId);
	// console.log("keyElement=%s", keyElement);
	if (keyElement != null) {
		key = keyElement.value;
		// console.log("key=%s", key);
		if (!key) {
			// keyに値が設定されていない場合はエラーリターン
			var message = keyName + "が指定されていません";
			console.log("%s", message);
			return {
				rc : CIPHER.NG,
				value : null,
				message : message
			};
		}
	} else {
		// 項目が存在しない場合はundefinedを返却する。
		var message = keyName + "がありません";
		console.log("%s", message);
		return {
			rc : CIPHER.UNDEF,
			value : null,
			message : message
		};
	}

	// 確認用パスフレーズと一致するか確認する
	if (!reKeyElementId) {
		// 省略された場合は処理なし
	} else {
		var reKeyElement = document.getElementById(reKeyElementId);
		// console.log("reKeyElement=%s", reKeyElement);
		if (reKeyElement != null) {
			var reKey = reKeyElement.value;
			// console.log("key=%s", key);
			if (!reKey) {
				// keyに値が設定されていない場合はエラーリターン
				var message = keyName + "(確認用)が指定されていません";
				console.log("%s", message);
				return {
					rc : CIPHER.NG,
					value : null,
					message : message
				};
			}
			if (key !== reKey) {
				// パスフレーズと確認用パスフレーズが一致しない場合はエラーリターン
				var message = keyName + "(確認用)が一致しません";
				console.log("%s", message);
				return {
					rc : CIPHER.UNMATCH,
					value : null,
					message : message
				};
			}
		} else {
			// 項目が存在しない場合はundefinedを返却する。
			var message = keyName + "(確認用)がありません";
			console.log("%s", message);
			return {
				rc : CIPHER.UNDEF,
				value : null,
				message : message
			};
		}
	}

	// パスフレーズの取得処理
	try {
		// パスフレーズを32Byteに変換してpassphraseに設定する
		var passphrase = GetAes256Passphrase(key);
		console.log("key=%s, passphrase=%s", key, passphrase);
		return {
			rc : CIPHER.OK,
			value : passphrase,
			message : ""
		};
	} catch (e) {
		// エラーが発生したときの処理
		var message = keyName + "の形式が不正です";
		console.log("%s", message);
		return {
			rc : CIPHER.NG,
			value : null,
			message : message
		};
	}

}

/**
 * セキュリティレベル取得関数 ・FORMからセキュリティレベルを取得する。
 */
function GetLevel(levelElementId) {
	console.log("GetLevel（levelElementId=%s", levelElementId);

	// パラメタチェック（指定されていない場合はNULLを返却する）
	if (!levelElementId) {
		console.log("セキュリティレベルが指定されていません");
		return {
			rc : CIPHER.NG,
			value : null,
			message : "セキュリティレベルが指定されていません"
		};
	}

	// セキュリティレベルを取り出す ※<select id="selectLevel">の値を取り出す
	var levelElement = document.getElementById(levelElementId);
	if (levelElement == null) {
		console.log("項目（%s）がありません", levelElementId);
		return {
			rc : CIPHER.NG,
			value : null,
			message : "項目（" + levelElementId + "）がありません"
		};
	}

	// セキュリティレベルを取得する
	// ※セキュリティレベルはリストボックスか、テキストと割り切って値を取得する
	console.log("levelElement.type=%s", levelElement.type);
	var level;
	if (levelElement.type === "select-one") {
		var options = document.getElementById(levelElementId).options;
		level = options.item(levelElement.selectedIndex).value;
	} else {
		level = levelElement.value;
	}

	console.log("セキュリティレベル=%s", level);
	return {
		rc : CIPHER.OK,
		value : level,
		message : ""
	};

}

/**
 * フォーム項目暗号化関数 （レベル０用）
 */
function EncryptItem0(encrypt0ElementId) {

	console.log("EncryptItem0（encrypt0ElementId=%s)", encrypt0ElementId);

	// 項目が指定されていない場合は正常リターンする
	if (!encrypt0ElementId) {
		return {
			rc : CIPHER.OK,
			level : CIPHER.LEVEL0,
			encrypt0value : "",
			encrypt1value : null,
			encrypt2value : null,
			message : ""
		};
	}

	// セキュリティレベル0で暗号化する文字列を取り出す
	var encryptElement = document.getElementById(encrypt0ElementId);
	if (encryptElement == null) {
		// FORMの項目が見つからない場合はエラーリターン
		console.log("項目（%s）がありません", encrypt0ElementId);
		return {
			rc : CIPHER.NG,
			level : CIPHER.LEVEL0,
			encrypt0value : null,
			encrypt1value : null,
			encrypt2value : null,
			message : "項目（" + encrypt0ElementId + "）がありません"
		};
	}
	var encryptValue = encryptElement.value;
	try {
		var encrypted = Encrypt0(encryptValue);
		if (encrypted.rc !== CIPHER.OK) {
			// 暗号化に失敗した場合はエラーリターンする
			return {
				rc : CIPHER.NG,
				level : CIPHER.LEVEL0,
				encrypt0value : null,
				encrypt1value : null,
				encrypt2value : null,
				message : encrypted.message
			};
		}
		return {
			rc : CIPHER.OK,
			level : CIPHER.LEVEL0,
			encrypt0value : encryptValue,
			encrypt1value : null,
			encrypt2value : null,
			message : ""
		};
	} catch (e) {
		// エラーメッセージを作成する
		var message = e.message;
		console.log("暗号化失敗：%s", message);
		return {
			rc : CIPHER.NG,
			level : level,
			encrypt0value : null,
			encrypt1value : null,
			encrypt2value : null,
			message : message
		};
	}

}

/**
 * フォーム項目暗号化関数 ・セキュリティレベルとパスフレーズの入力状況によりフォーム項目を暗号化する。
 */
function EncryptItem1(passphrase1name, passphrase1, encrypt0ElementId,
		encrypt1ElementId) {

	console
			.log(
					"EncryptItem1（passphrase1name=%s, passphrase1=%s, encrypt0ElementId=%s,encrypt1ElementId=%s)",
					passphrase1name, passphrase1, encrypt0ElementId,
					encrypt1ElementId);

	var level = CIPHER.LEVEL1;
	var encrypt0value = null;
	var encrypt1value = null;
	var encrypt2value = null;

	// セキュリティレベル0で暗号化する文字列を取り出す
	var encrypted0 = EncryptItem0(encrypt0ElementId);
	if (encrypted0.rc === CIPHER.OK) {
		encrypt0value = encrypted0.encrypt0value;
	}

	// セキュリティレベル1で暗号化する文字列を取り出す
	var encrypt1Element = document.getElementById(encrypt1ElementId);
	if (encrypt1Element == null) {
		// FORMの項目が見つからない場合はエラーリターン
		console.log("項目（%s）がありません", encrypt1ElementId);
		return {
			rc : CIPHER.NG,
			level : level,
			encrypt0value : encrypt0value,
			encrypt1value : null,
			encrypt2value : null,
			message : "項目（" + encrypt1ElementId + "）がありません"
		};
	}
	try {
		var encrypted1 = Encrypt1(encrypt1Element.value, passphrase1name,
				passphrase1);
		if (encrypted1.rc !== CIPHER.OK) {
			// 暗号化に失敗した場合はエラーリターンする
			return {
				rc : CIPHER.NG,
				level : level,
				encrypt0value : encrypt0value,
				encrypt1value : null,
				encrypt2value : null,
				message : encrypted1.message
			};
		}
		return {
			rc : CIPHER.OK,
			level : level,
			encrypt0value : encrypt0value,
			encrypt1value : encrypted1.encryptedValue,
			encrypt2value : null,
			message : ""
		};
	} catch (e) {
		// エラーメッセージを作成する
		var message = e.message;
		console.log("暗号化失敗：%s", message);
		return {
			rc : CIPHER.NG,
			level : level,
			encrypt0value : encrypt0value,
			encrypt1value : null,
			encrypt2value : null,
			message : message
		};
	}

}

/**
 * フォーム項目暗号化関数 ・セキュリティレベルとパスフレーズの入力状況によりフォーム項目を暗号化する。
 */
function EncryptItem2(passphrase1name, passphrase1, passphrase2name,
		passphrase2, encrypt0ElementId, encrypt1ElementId, encrypt2ElementId) {

	console
			.log(
					"EncryptItem2（passphrase1name=%s, passphrase1=%s, passphrase2name=%s, passphrase2=%s, encrypt0ElementId=%s,encrypt1ElementId=%s,encrypt2ElementId=%s)",
					passphrase1name, passphrase1, passphrase2name, passphrase2,
					encrypt0ElementId, encrypt1ElementId, encrypt2ElementId);

	var level = CIPHER.LEVEL2;
	var encrypt0value = null;
	var encrypt1value = null;
	var encrypt2value = null;

	// セキュリティレベル0で暗号化する文字列を取り出す
	var encrypted1 = EncryptItem1(passphrase1name, passphrase1,
			encrypt0ElementId, encrypt1ElementId);
	if (encrypted1.rc == CIPHER.OK) {
		encrypt0value = encrypted1.encrypt0value;
		encrypt1value = encrypted1.encrypt1value;
	}

	// セキュリティレベル1で暗号化する文字列を取り出す
	var encrypt2Element = document.getElementById(encrypt2ElementId);
	if (encrypt2Element == null) {
		// FORMの項目が見つからない場合はエラーリターン
		console.log("項目（%s）がありません", encrypt2ElementId);
		return {
			rc : CIPHER.NG,
			level : level,
			encrypt0value : encrypt0value,
			encrypt1value : encrypt1value,
			encrypt2value : null,
			message : "項目（" + encrypt1ElementId + "）がありません"
		};
	}
	try {
		var encrypted2 = Encrypt2(encrypt2Element.value, passphrase1name,
				passphrase1, passphrase2name, passphrase2);
		if (encrypted2.rc !== CIPHER.OK) {
			// 暗号化に失敗した場合はエラーリターンする
			return {
				rc : CIPHER.NG,
				level : level,
				encrypt0value : encrypt0value,
				encrypt1value : encrypt1value,
				encrypt2value : null,
				message : encrypted2.message
			};
		}
		return {
			rc : CIPHER.OK,
			level : level,
			encrypt0value : encrypt0value,
			encrypt1value : encrypt1value,
			encrypt2value : encrypted2.encryptedValue,
			message : ""
		};
	} catch (e) {
		// エラーメッセージを作成する
		var message = e.message;
		console.log("暗号化失敗：%s", message);
		return {
			rc : CIPHER.NG,
			level : level,
			encrypt0value : encrypt0value,
			encrypt1value : encrypt1value,
			encrypt2value : null,
			message : message
		};
	}

}

/**
 * フォーム項目暗号化関数 ・セキュリティレベルとパスフレーズの入力状況によりフォーム項目を暗号化する。
 */
function EncryptItem(passphrase1name, passphrase1, passphrase2name,
		passphrase2, levelElementId, encrypt0ElementId, encrypt1ElementId,
		encrypt2ElementId) {

	console
			.log(
					"EncryptItem（passphrase1name=%s, passphrase1=%s, passphrase2name=%s, passphrase2=%s, levelElementId=%s, encrypt0ElementId=%s,encrypt1ElementId=%s, encrypt2ElementId=%s)",
					passphrase1name, passphrase1, passphrase2name, passphrase2,
					levelElementId, encrypt0ElementId, encrypt1ElementId,
					encrypt2ElementId);

	var levelElement = GetLevel(levelElementId);
	if (levelElement.rc !== CIPHER.OK) {
		// セキュリティレベルが取得できない場合はエラーリターンする
		console.log("セキュリティレベルが取得できない：%s", levelElement.message);
		return {
			rc : CIPHER.NG,
			level : null,
			encrypt0value : null,
			encrypt1value : null,
			encrypt2value : null,
			message : levelElement.message
		};
	}
	var level = levelElement.value;
	console.log("セキュリティレベル=%s", level);

	// セキュリティレベル毎の暗号化処理
	if (level === CIPHER.LEVEL0) {
		// セキュリティレベル0の暗号化処理
		return EncryptItem0(encrypt0ElementId);
	} else if (level === CIPHER.LEVEL1) {
		// セキュリティレベル1の暗号化処理
		return EncryptItem1(passphrase1name, passphrase1, encrypt0ElementId,
				encrypt1ElementId);
	} else if (level === CIPHER.LEVEL2) {
		// セキュリティレベル2の暗号化処理
		return EncryptItem2(passphrase1name, passphrase1, passphrase2name,
				passphrase2, encrypt0ElementId, encrypt1ElementId,
				encrypt2ElementId);
	} else {
		console.log("サポートされていない暗号レベルが指定されました。レベル=%s", level);
		return {
			rc : CIPHER.NG,
			level : null,
			encrypt0value : null,
			encrypt1value : null,
			encrypt2value : null,
			message : "サポートされていない暗号レベルが指定されました。レベル=" + level
		};
	}
}

/**
 * フォーム項目復号化関数 ・セキュリティレベルとパスフレーズの入力状況によりフォーム項目を復号化する。
 */
function DecryptItem0(encrypted0ElementId) {

	console.log("DecryptItem0（encrypted0ElementId=%s)", encrypted0ElementId);

	var level = CIPHER.LEVEL0;

	// 項目が指定されていない場合は正常リターンする
	if (!encrypted0ElementId) {
		return {
			rc : CIPHER.OK,
			level : level,
			decryptedValue : "",
			message : ""
		};
	}

	// セキュリティレベル0で暗号化する文字列を取り出す
	var encryptedElement = document.getElementById(encrypted0ElementId);
	if (encryptedElement == null) {
		// FORMの項目が見つからない場合はエラーリターン
		console.log("項目（%s）がありません", encrypted0ElementId);
		return {
			rc : CIPHER.NG,
			level : level,
			decryptedValue : null,
			message : "項目（" + encrypted0ElementId + "）がありません"
		};
	}
	var encryptedValue = encryptedElement.value;
	console.log("encryptedValue=%s", encryptedValue);
	try {
		var decrypted = Decrypt0(encryptedValue);
		if (decrypted.rc !== CIPHER.OK) {
			// 暗号化に失敗した場合はエラーリターンする
			return {
				rc : CIPHER.NG,
				level : level,
				decryptedValue : null,
				message : decrypted.message
			};
		}

		console.log('rc --> %s', decrypted.rc);
		console.log('level --> %s', decrypted.level);
		console.log('decryptedValue --> %s', decrypted.decryptedValue);
		console.log('message --> %s', decrypted.message);

		return {
			rc : CIPHER.OK,
			level : level,
			decryptedValue : decrypted.decryptedValue,
			message : ""
		};
	} catch (e) {
		// エラーメッセージを作成する
		var message = e.message;
		console.log("復号化失敗：%s", message);
		return {
			rc : CIPHER.NG,
			level : level,
			decryptedValue : null,
			message : message
		};
	}

}

/**
 * フォーム項目復号化関数 ・セキュリティレベルとパスフレーズの入力状況によりフォーム項目を復号化する。
 */
function DecryptItem1(passphrase1name, passphrase1, encrypted0ElementId,
		encrypted1ElementId) {

	console
			.log(
					"DecryptItem1（passphrase1name=%s, passphrase1=%s, encrypt0ElementId=%s, encrypt1ElementId=%s)",
					passphrase1name, passphrase1, encrypted0ElementId,
					encrypted1ElementId);

	var level = CIPHER.LEVEL1;
	var decryptedValue = null;

	// セキュリティレベル0で暗号化する文字列を取り出す
	var decrypted0 = DecryptItem0(encrypted0ElementId);

	console.log('rc --> %s', decrypted0.rc);
	console.log('level --> %s', decrypted0.level);
	console.log('decryptedValue --> %s', decrypted0.decryptedValue);
	console.log('message --> %s', decrypted0.message);

	decryptedValue = decrypted0.decryptedValue;
	if (decrypted0.rc !== CIPHER.OK) {
		return {
			rc : CIPHER.NG,
			level : level,
			decryptedValue : decryptedValue,
			message : decrypted0.message
		};
	}

	// 項目が指定されていない場合は正常リターンする
	if (!encrypted1ElementId) {
		return {
			rc : CIPHER.OK,
			level : level,
			decryptedValue : decryptedValue,
			message : ""
		};
	}

	// セキュリティレベル1で暗号化する文字列を取り出す
	var encrypted1Element = document.getElementById(encrypted1ElementId);
	if (encrypted1Element == null) {
		// FORMの項目が見つからない場合はエラーリターン
		console.log("項目（%s）がありません", encrypted1ElementId);
		return {
			rc : CIPHER.NG,
			level : level,
			decryptedValue : decryptedValue,
			message : "項目（" + encrypted1ElementId + "）がありません"
		};
	}
	var encryptedValue = encrypted1Element.value;
	console.log("encryptedValue=%s", encryptedValue);
	try {
		var decrypted = Decrypt1(encryptedValue, passphrase1name, passphrase1);

		console.log('rc --> %s', decrypted.rc);
		console.log('level --> %s', decrypted.level);
		console.log('decryptedValue --> %s', decrypted.decryptedValue);
		console.log('message --> %s', decrypted.message);

		if (decrypted.rc !== CIPHER.OK) {
			// 暗号化に失敗した場合はエラーリターンする
			return {
				rc : CIPHER.NG,
				level : level,
				decryptedValue : decryptedValue,
				message : decrypted.message
			};
		}
		return {
			rc : CIPHER.OK,
			level : level,
			decryptedValue : decrypted.decryptedValue,
			message : ""
		};
	} catch (e) {
		// エラーメッセージを作成する
		var message = e.message;
		console.log("復号化失敗：%s", message);
		return {
			rc : CIPHER.NG,
			level : level,
			decryptedValue : decryptedValue,
			message : message
		};
	}

}

/**
 * フォーム項目復号化関数 ・セキュリティレベルとパスフレーズの入力状況によりフォーム項目を復号化する。
 */
function DecryptItem2(passphrase1name, passphrase1, passphrase2name,
		passphrase2, encrypted0ElementId, encrypted1ElementId,
		encrypted2ElementId) {

	console
			.log(
					"DecryptItem2（passphrase1name=%s, passphrase1=%s, passphrase2name=%s, passphrase2=%s, encrypted0ElementId=%s, encrypted1ElementId=%s, encrypted2ElementId=%s)",
					passphrase1name, passphrase1, passphrase2name, passphrase2,
					encrypted0ElementId, encrypted1ElementId,
					encrypted2ElementId);

	var level = CIPHER.LEVEL2;
	var decryptedValue = null;

	// セキュリティレベル0で暗号化する文字列を取り出す
	var decrypted1 = DecryptItem1(passphrase1name, passphrase1,
			encrypted0ElementId, encrypted1ElementId);

	console.log('rc --> %s', decrypted1.rc);
	console.log('level --> %s', decrypted1.level);
	console.log('decryptedValue --> %s', decrypted1.decryptedValue);
	console.log('message --> %s', decrypted1.message);

	decryptedValue = decrypted1.decryptedValue;
	if (decrypted1.rc !== CIPHER.OK) {
		return {
			rc : CIPHER.NG,
			level : level,
			decryptedValue : decryptedValue,
			message : decrypted1.message
		};
	}

	// 項目が指定されていない場合は正常リターンする
	if (!encrypted2ElementId) {
		return {
			rc : CIPHER.OK,
			level : level,
			decryptedValue : decryptedValue,
			message : ""
		};
	}

	// セキュリティレベル1で暗号化する文字列を取り出す
	var encrypted2Element = document.getElementById(encrypted2ElementId);
	if (encrypted2Element == null) {
		// FORMの項目が見つからない場合はエラーリターン
		console.log("項目（%s）がありません", encrypted2ElementId);
		return {
			rc : CIPHER.NG,
			level : level,
			decryptedValue : decryptedValue,
			message : "項目（" + encrypted2ElementId + "）がありません"
		};
	}
	var encryptedValue = encrypted2Element.value;
	console.log("encryptedValue=%s", encryptedValue);
	try {
		var decrypted = Decrypt2(encryptedValue, passphrase1name, passphrase1,
				passphrase2name, passphrase2);

		console.log('rc --> %s', decrypted.rc);
		console.log('level --> %s', decrypted.level);
		console.log('decryptedValue --> %s', decrypted.decryptedValue);
		console.log('message --> %s', decrypted.message);

		if (decrypted.rc !== CIPHER.OK) {
			// 暗号化に失敗した場合はエラーリターンする
			return {
				rc : CIPHER.NG,
				level : level,
				decryptedValue : decryptedValue,
				message : decrypted.message
			};
		}
		return {
			rc : CIPHER.OK,
			level : level,
			decryptedValue : decrypted.decryptedValue,
			message : ""
		};
	} catch (e) {
		// エラーメッセージを作成する
		var message = e.message;
		console.log("復号化失敗：%s", message);
		return {
			rc : CIPHER.NG,
			level : level,
			decryptedValue : decryptedValue,
			message : message
		};
	}

}

/**
 * フォーム項目復号化関数 ・セキュリティレベルとパスフレーズの入力状況によりフォーム項目を復号化する。
 */
function DecryptItem(passphrase1name, passphrase1, passphrase2name,
		passphrase2, levelElementId, encrypted0ElementId, encrypted1ElementId,
		encrypted2ElementId) {

	console
			.log(
					"DecryptItem（passphrase1name=%s, passphrase1=%s, passphrase2name=%s, passphrase2=%s, levelElementId=%s, encrypted0ElementId=%s,encrypted1ElementId=%s, encrypted2ElementId=%s)",
					passphrase1name, passphrase1, passphrase2name, passphrase2,
					levelElementId, encrypted0ElementId, encrypted1ElementId,
					encrypted2ElementId);

	var levelElement = GetLevel(levelElementId);
	if (levelElement.rc !== CIPHER.OK) {
		// セキュリティレベルが取得できない場合はエラーリターンする
		console.log("セキュリティレベルが取得できない：%s", levelElement.message);
		return {
			rc : CIPHER.NG,
			level : null,
			decryptedValue : null,
			message : levelElement.message
		};
	}
	var level = levelElement.value;
	console.log("セキュリティレベル=%s", level);

	// セキュリティレベル毎の暗号化処理
	if (level === CIPHER.LEVEL0) {
		// セキュリティレベル0の暗号化処理
		return DecryptItem0(encrypted0ElementId);
	} else if (level === CIPHER.LEVEL1) {
		// セキュリティレベル1の暗号化処理
		return DecryptItem1(passphrase1name, passphrase1, encrypted0ElementId,
				encrypted1ElementId);
	} else if (level === CIPHER.LEVEL2) {
		// セキュリティレベル2の暗号化処理
		return DecryptItem2(passphrase1name, passphrase1, passphrase2name,
				passphrase2, encrypted0ElementId, encrypted1ElementId,
				encrypted2ElementId);
	} else {
		console.log("サポートされていない暗号レベルが指定されました。レベル=%s", level);
		return {
			rc : CIPHER.NG,
			level : null,
			decryptedValue : null,
			message : "サポートされていない暗号レベルが指定されました。レベル=" + level
		};
	}
}

/**
 * 例外オブジェクトからスタックトレースを出力する関数
 */
function PrintStackTrace(e) {

	if (e.stack) {
		// 出力方法は、使いやすいように修正する。
		error(e.stack);
	} else {
		// stackがない場合には、そのままエラー情報を出す。
		error(e.message, e);
	}

}
