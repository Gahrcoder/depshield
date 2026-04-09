// BroadcastChannel without sender validation
const channel = new BroadcastChannel('app-sync');

channel.onmessage = function(event) {
  // No validation of who sent this message
  if (event.data.type === 'STATE_UPDATE') {
    applyStateUpdate(event.data.payload);
  }
};

function broadcastUpdate(data) {
  channel.postMessage({ type: 'STATE_UPDATE', payload: data });
}
