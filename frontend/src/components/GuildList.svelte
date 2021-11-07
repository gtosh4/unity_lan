<script lang="ts">
  import { Card, List } from "smelte";
  import type { APIGuild } from "discord-api-types/payloads/v9";
  import { wailsStore } from "../wails_store";

  const guilds = wailsStore<APIGuild[]>("Guilds");

  $: items =
    $guilds?.map((g) => {
      return {
        text: g.name,
      };
    }) || [];
</script>

<Card.Card classes="w-full">
  <List {items} />
</Card.Card>

<style global>
</style>
