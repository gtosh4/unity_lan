import App from './App.svelte';

import * as Wails from '@wailsapp/runtime';

import "smelte/src/tailwind.css";

let app

Wails.Init(() => {
	app = new App({
		target: document.body,
	});
});

export default app;
