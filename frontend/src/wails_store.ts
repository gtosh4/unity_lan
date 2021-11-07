import { Events, Store } from "@wailsapp/runtime";
import { writable, Writable } from "svelte/store";

export function wailsStore<T>(name: string): Writable<T> {
  const s = Store.New(name)
  const w = writable<T>()

  let initialized = false
  let updating = false
  const wrapUpdate = (f) => {
    if (!updating && initialized) {
      updating = true
      try {
        f()
      } finally {
        updating = false
      }
    }
  }
  s.subscribe(v => {
    wrapUpdate(() => w.set(v))
  })
  w.subscribe(v => {
    if (v) {
      wrapUpdate(() => s.set(v))
    }
  })
  initialized = true

  Events.Emit(`wails:sync:store:requestvalue:${name}`)

  return w
}
