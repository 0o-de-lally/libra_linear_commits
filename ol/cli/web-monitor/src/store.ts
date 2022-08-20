import { writable } from 'svelte/store'

export const chainInfo = writable('Chain');
chainInfo.set("{}");

export const valsInitView = writable([]);


let uri = "http://" + location.host + "/vitals";
let sse = new EventSource(uri);

sse.onmessage = function (msg) {
  chainInfo.update(existing => msg.data)
}