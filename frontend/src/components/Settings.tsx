// frontend/src/components/Settings.tsx
import React, { useEffect, useMemo, useState } from "react";

type ModeState = { mode: "live" | "pcap" | string; iface?: string | null; pcap_path?: string | null };
const API = (path: string) => `http://localhost:8000${path}`;

export default function Settings() {
  const [loading, setLoading] = useState(false);
  const [state, setState] = useState<ModeState | null>(null);
  const [ifaces, setIfaces] = useState<string[]>([]);
  const [ifaceSel, setIfaceSel] = useState<string>("");

  const badge = useMemo(() => {
    if (!state) return null;
    const color = state.mode === "live" ? "bg-emerald-600" : "bg-sky-600";
    const label = state.mode === "live" ? "LIVE" : "PCAP";
    return <span className={`inline-flex items-center px-2 py-1 text-xs font-semibold text-white rounded ${color}`}>{label}</span>;
  }, [state]);

  async function fetchState() {
    const s = await fetch(API("/api/mode")).then(r => r.json());
    setState(s);
    if (s.iface) setIfaceSel(s.iface);
  }
  async function fetchIfaces() {
    const list = await fetch(API("/api/interfaces")).then(r => r.json());
    setIfaces(list || []);
    if (!ifaceSel && list && list.length) setIfaceSel(list[0]);
  }

  useEffect(() => { fetchState(); fetchIfaces(); }, []);

  async function switchLive() {
    try {
      setLoading(true);
      const body = { mode: "live", iface: ifaceSel || state?.iface };
      const s = await fetch(API("/api/mode"), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then(r => r.json());
      setState(s);
      alert(`Switched to LIVE on iface=${s.iface}`);
    } catch (e:any) {
      alert(`Failed to switch to LIVE: ${e?.message || e}`);
    } finally {
      setLoading(false);
    }
  }

  async function switchPcap(pcapPath?: string) {
    try {
      setLoading(true);
      const body = { mode: "pcap", pcap_path: pcapPath || state?.pcap_path || "data/sample.pcap" };
      const s = await fetch(API("/api/mode"), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then(r => r.json());
      setState(s);
      alert(`Switched to PCAP (${s.pcap_path})`);
    } catch (e:any) {
      alert(`Failed to switch to PCAP: ${e?.message || e}`);
    } finally {
      setLoading(false);
    }
  }

  async function onUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const form = new FormData();
    form.append("file", file);
    setLoading(true);
    try {
      const res = await fetch(API("/api/pcap"), { method: "POST", body: form }).then(r => r.json());
      await switchPcap(res.pcap_path);
    } catch (e:any) {
      alert(`Upload failed: ${e?.message || e}`);
    } finally {
      setLoading(false);
      e.currentTarget.value = "";
    }
  }

  return (
    <div className="p-6 space-y-6">
      <header className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Settings</h1>
        <div className="flex items-center gap-3">
          <span className="text-sm text-gray-400">Current Mode</span>
          {badge}
        </div>
      </header>

      <section className="rounded-2xl border border-gray-800 p-5 space-y-4">
        <h2 className="font-medium">Live Capture</h2>
        <div className="grid md:grid-cols-3 gap-3">
          <div className="col-span-2">
            <label className="block text-sm mb-1">Network Interface</label>
            <select
              className="w-full rounded-lg bg-gray-900 border border-gray-700 p-2"
              value={ifaceSel}
              onChange={(e) => setIfaceSel(e.target.value)}
            >
              {ifaces.map((n) => (<option key={n} value={n}>{n}</option>))}
            </select>
            <p className="text-xs text-gray-500 mt-1">On Windows, ensure Npcap is installed and backend runs as Administrator.</p>
          </div>
          <div className="flex items-end">
            <button
              onClick={switchLive}
              disabled={loading || !ifaceSel}
              className="w-full rounded-xl bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 px-4 py-2 font-medium"
            >
              Switch to Live Mode
            </button>
          </div>
        </div>
      </section>

      <section className="rounded-2xl border border-gray-800 p-5 space-y-4">
        <h2 className="font-medium">PCAP Mode</h2>
        <div className="grid md:grid-cols-3 gap-3 items-end">
          <div className="col-span-2">
            <label className="block text-sm mb-1">Upload PCAP</label>
            <input type="file" accept=".pcap,.pcapng" onChange={onUpload}
              className="w-full text-sm file:mr-4 file:rounded-lg file:border-0 file:bg-sky-700 file:px-4 file:py-2 file:text-white hover:file:bg-sky-600"/>
            <p className="text-xs text-gray-500 mt-1">After upload, the app switches to that file automatically.</p>
          </div>
          <button
            onClick={() => switchPcap()}
            disabled={loading}
            className="w-full rounded-xl bg-sky-600 hover:bg-sky-500 disabled:opacity-50 px-4 py-2 font-medium"
          >
            Use Default sample.pcap
          </button>
        </div>
        {state?.pcap_path && (
          <p className="text-xs text-gray-400">Current PCAP: {state.pcap_path}</p>
        )}
      </section>
    </div>
  );
}
