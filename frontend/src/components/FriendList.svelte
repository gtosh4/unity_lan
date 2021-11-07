<script lang="ts">
  import type { APIUser } from "discord-api-types";

  import { Card, List } from "smelte";
  import { wailsStore } from "../wails_store";

  interface Relationship {
    user: APIUser;
    type: number;
    id: string;
  }

  const friends = wailsStore<Relationship[]>("Friends");

  $: items =
    $friends?.map((f) => {
      return {
        text: f.user.username,
      };
    }) || [];
</script>

<Card.Card classes="w-full">
  <List {items} />
</Card.Card>

<style global>
</style>
