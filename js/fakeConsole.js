try {
	if(!window.console) {
		var FakeConsole = function(){};
		FakeConsole.prototype = {
			log: function(){},
			debug: function(){},
			info: function(){},
			warn: function(){},
			error: function(){},
			assert: function(){},
			clear: function(){},
			dir: function(){},
			dirxml: function(){},
			trace: function(){},
			group: function(){},
			groupCollapsed: function(){},
			groupEnd: function(){},
			time: function(){},
			timeEnd: function(){},
			profile: function(){},
			profileEnd: function(){},
			count: function(){},
			exception: function(){},
			table: function(){}
		};
		var console = new FakeConsole();
	}
} catch(err) {
}
