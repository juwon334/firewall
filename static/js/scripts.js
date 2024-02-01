/*!
 * Start Bootstrap - SB Admin v7.0.7 (https://startbootstrap.com/template/sb-admin)
 * Copyright 2013-2023 Start Bootstrap
 * Licensed under MIT (https://github.com/StartBootstrap/startbootstrap-sb-admin/blob/master/LICENSE)
 */
//
// Scripts
//

window.addEventListener("DOMContentLoaded", (event) => {
	// Toggle the side navigation
	const sidebarToggle = document.body.querySelector("#sidebarToggle");
	if (sidebarToggle) {
		// Uncomment Below to persist sidebar toggle between refreshes
		// if (localStorage.getItem('sb|sidebar-toggle') === 'true') {
		//     document.body.classList.toggle('sb-sidenav-toggled');
		// }
		sidebarToggle.addEventListener("click", (event) => {
			event.preventDefault();
			document.body.classList.toggle("sb-sidenav-toggled");
			localStorage.setItem("sb|sidebar-toggle", document.body.classList.contains("sb-sidenav-toggled"));
		});
	}
});

// 규칙 삭제 함수
function deleteRule(rule) {
	var new_rule = 0;
	var rule1 = rule.split(" ")[0];
	console.log(rule1);

	if (rule1 == "<span") {
		new_rule = rule.split(" ")[1].split(">")[1];
	} else {
		new_rule = rule1;
	}

	fetch("/delete_rule/" + new_rule, {
		method: "POST",
	})
		.then((response) => response.json())
		.then((data) => {
			if (data.success) {
				alert(data.message);
				location.reload(); // 페이지 새로고침
			} else {
				alert("Error: " + data.message);
			}
		})
		.catch((error) => console.error("Error:", error));
}

function ParseRule(rule) {
	var new_rule = 0;
	var rule1 = rule.split(" ")[0];
	console.log(rule1);

	if (rule1 == "<span") {
		new_rule = rule.split(" ")[1].split(">")[1];
	} else {
		new_rule = rule1;
	}
	return new_rule;
}

document.addEventListener('DOMContentLoaded', function() {
    var ruleDataElements = document.querySelectorAll('.rule-data');

    ruleDataElements.forEach(function(element) {
        var rule = element.getAttribute('data-rule');
        var parsedRule = ParseRule(rule); // 여기서 parseRule 함수를 호출합니다.

        // parsedRule 결과를 element의 내용으로 설정합니다.
        element.textContent = parsedRule.join(' '); // 예시: 배열을 문자열로 변환
    });
});
