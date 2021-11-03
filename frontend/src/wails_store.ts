import { Store } from "@wailsapp/runtime";
import { writable, Writable } from "svelte/store";

export function wailsStore<T>(name: string, init?: T): Writable<T> {
  const s = Store.New(name)
  const w = writable<T>(init)

  let updating = false
  const wrapUpdate = (f) => {
    if (!updating) {
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
  let initialized = false
  w.subscribe(v => {
    if (v && initialized) {
      wrapUpdate(() => s.set(v))
    }
    initialized = true
  })

  return w
}
