function tr_default(tblID) {
	var vTR = "table" + tblID;
	//$(vTR).css("background-color", "#ffffff");
	// ヘッダ行の色を設定
	//$(vTR + ' th').css('background-color', '#b0c4de');
	// 偶数行の色を設定
	tr_even(vTR);
	// 奇数行の色を設定
	tr_odd(vTR);
	$(vTR + ' tr').mouseover(function() {
		$(this).css("background-color", "#00ffff").css("cursor", "pointer")
	});
	$(vTR + ' tr').mouseout(function() {
		$(this).css("background-color", "#ffffff").css("cursor", "normal")
		// 偶数行の色を設定
		tr_even(vTR);
		// 奇数行の色を設定
		tr_odd(vTR);
	});
}

function tr_click(trID) {
	trID.css("background-color", "#e49e61");
	trID.mouseover(function() {
		$(this).css("background-color", "#00ffff").css("cursor", "pointer")
	});
	trID.mouseout(function() {
		 $(this).css("background-color", "#00ffff").css("cursor", "normal")
	});
}

// 偶数行の色を設定
function tr_even(vTR) {
	$(vTR + ' tr:even').css('background-color', '#e6e6fa');
}

// 奇数行の色を設定
function tr_odd(vTR) {
	$(vTR + ' tr:odd').css('background-color', '#fafad2');
}
