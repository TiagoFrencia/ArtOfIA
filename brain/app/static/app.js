const terminal = new Terminal({
  cursorBlink: true,
  fontFamily: '"Cascadia Code", "Fira Code", monospace',
  fontSize: 14,
  rows: 28,
  cols: 110,
  theme: {
    background: "#08111f",
    foreground: "#d6e4ff",
    cursor: "#8cf2d6",
    black: "#08111f",
    red: "#ff6b81",
    green: "#8cf2d6",
    yellow: "#ffd166",
    blue: "#65b5ff",
    magenta: "#e599f7",
    cyan: "#67e8f9",
    white: "#edf2ff",
  },
});

terminal.open(document.getElementById("terminal"));
terminal.writeln("Iniciando consola del worker...");

const statusEl = document.getElementById("status");
const reconnectButton = document.getElementById("reconnectButton");
let socket = null;

function setStatus(text, variant = "info") {
  statusEl.textContent = text;
  statusEl.dataset.variant = variant;
}

function connect() {
  if (socket && socket.readyState === WebSocket.OPEN) {
    socket.close();
  }

  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  socket = new WebSocket(`${protocol}://${window.location.host}/ws`);

  socket.addEventListener("open", () => {
    setStatus("Conectado al brain y al worker", "ok");
    terminal.focus();
    sendResize();
  });

  socket.addEventListener("message", (event) => {
    if (event.data === "__pong__") {
      return;
    }
    terminal.write(event.data);
  });

  socket.addEventListener("close", () => {
    setStatus("Conexion cerrada", "warn");
    terminal.writeln("\r\n[ui] la conexion se cerro.");
  });

  socket.addEventListener("error", () => {
    setStatus("Error de conexion", "error");
    terminal.writeln("\r\n[ui] hubo un error al conectar.");
  });
}

function sendResize() {
  if (!socket || socket.readyState !== WebSocket.OPEN) {
    return;
  }
  socket.send(`__resize__:${terminal.cols}:${terminal.rows}`);
}

terminal.onData((data) => {
  if (!socket || socket.readyState !== WebSocket.OPEN) {
    return;
  }
  socket.send(data);
});

window.addEventListener("resize", sendResize);
reconnectButton.addEventListener("click", connect);

setInterval(() => {
  if (socket && socket.readyState === WebSocket.OPEN) {
    socket.send("__ping__");
  }
}, 10000);

connect();
