// Run once to generate backend/public/data/landmarks.js
// Usage: node scripts/fetch-landmark-photos.js
// Requires Node 20+ (uses built-in fetch)

const { writeFileSync } = require('fs');
const { join } = require('path');

const OUT = join(__dirname, '../backend/public/data/landmarks.js');

const SEED = [
  // Europe
  { name: "Eiffel Tower",               iso: 250, wiki: "Eiffel_Tower" },
  { name: "Mont Saint-Michel",           iso: 250, wiki: "Mont_Saint-Michel" },
  { name: "Colosseum",                   iso: 380, wiki: "Colosseum" },
  { name: "Trevi Fountain",              iso: 380, wiki: "Trevi_Fountain" },
  { name: "Big Ben",                     iso: 826, wiki: "Big_Ben" },
  { name: "Stonehenge",                  iso: 826, wiki: "Stonehenge" },
  { name: "Sagrada Família",             iso: 724, wiki: "Sagrada_Família" },
  { name: "Alhambra",                    iso: 724, wiki: "Alhambra" },
  { name: "Acropolis of Athens",         iso: 300, wiki: "Acropolis_of_Athens" },
  { name: "Neuschwanstein Castle",       iso: 276, wiki: "Neuschwanstein_Castle" },
  { name: "Brandenburg Gate",            iso: 276, wiki: "Brandenburg_Gate" },
  { name: "Kinderdijk Windmills",        iso: 528, wiki: "Kinderdijk" },
  { name: "Atomium",                     iso:  56, wiki: "Atomium" },
  { name: "Tower of Belém",              iso: 620, wiki: "Tower_of_Belém" },
  { name: "Charles Bridge",              iso: 203, wiki: "Charles_Bridge,_Prague" },
  { name: "Hungarian Parliament Building", iso: 348, wiki: "Hungarian_Parliament_Building" },
  { name: "Cliffs of Moher",             iso: 372, wiki: "Cliffs_of_Moher" },
  { name: "Wawel Castle",                iso: 616, wiki: "Wawel_Castle" },
  { name: "Matterhorn",                  iso: 756, wiki: "Matterhorn" },
  { name: "Schönbrunn Palace",           iso:  40, wiki: "Schönbrunn_Palace" },
  { name: "Bran Castle",                 iso: 642, wiki: "Bran_Castle" },
  { name: "Hagia Sophia",                iso: 792, wiki: "Hagia_Sophia" },
  { name: "Dubrovnik City Walls",        iso: 191, wiki: "Walls_of_Dubrovnik" },
  { name: "Bled Island",                 iso: 705, wiki: "Bled_Island" },
  { name: "Strokkur Geyser",             iso: 352, wiki: "Strokkur" },
  { name: "Tallinn Old Town",            iso: 233, wiki: "Old_Town,_Tallinn" },
  { name: "Cathedral of Saint Sava",     iso: 688, wiki: "Cathedral_of_Saint_Sava,_Belgrade" },

  // Asia
  { name: "Taj Mahal",                   iso: 356, wiki: "Taj_Mahal" },
  { name: "Hawa Mahal",                  iso: 356, wiki: "Hawa_Mahal" },
  { name: "Great Wall of China",         iso: 156, wiki: "Great_Wall_of_China" },
  { name: "Potala Palace",               iso: 156, wiki: "Potala_Palace" },
  { name: "Mount Fuji",                  iso: 392, wiki: "Mount_Fuji" },
  { name: "Fushimi Inari Shrine",        iso: 392, wiki: "Fushimi_Inari-taisha" },
  { name: "Angkor Wat",                  iso: 116, wiki: "Angkor_Wat" },
  { name: "Burj Khalifa",                iso: 784, wiki: "Burj_Khalifa" },
  { name: "Petronas Towers",             iso: 458, wiki: "Petronas_Towers" },
  { name: "Borobudur",                   iso: 360, wiki: "Borobudur" },
  { name: "Wat Arun",                    iso: 764, wiki: "Wat_Arun" },
  { name: "Shwedagon Pagoda",            iso: 104, wiki: "Shwedagon_Pagoda" },
  { name: "Bagan Temples",               iso: 104, wiki: "Bagan" },
  { name: "Swayambhunath",               iso: 524, wiki: "Swayambhunath" },
  { name: "Merlion",                     iso: 702, wiki: "Merlion" },
  { name: "Persepolis",                  iso: 364, wiki: "Persepolis" },
  { name: "Ha Long Bay",                 iso: 704, wiki: "Ha_Long_Bay" },
  { name: "Gyeongbokgung Palace",        iso: 410, wiki: "Gyeongbokgung" },
  { name: "Sigiriya",                    iso: 144, wiki: "Sigiriya" },
  { name: "Masjid al-Haram",             iso: 682, wiki: "Masjid_al-Haram" },
  { name: "Petra",                       iso: 400, wiki: "Petra,_Jordan" },

  // Africa
  { name: "Pyramids of Giza",            iso: 818, wiki: "Giza_pyramid_complex" },
  { name: "Table Mountain",              iso: 710, wiki: "Table_Mountain" },
  { name: "Mount Kilimanjaro",           iso: 834, wiki: "Mount_Kilimanjaro" },
  { name: "Rock-Hewn Churches of Lalibela", iso: 231, wiki: "Rock-hewn_churches_of_Lalibela" },
  { name: "Great Mosque of Djenné",      iso: 466, wiki: "Great_Mosque_of_Djenné" },
  { name: "Djemaa el-Fna",              iso: 504, wiki: "Djemaa_el-Fna" },
  { name: "Amphitheatre of El Jem",      iso: 788, wiki: "Amphitheatre_of_El_Jem" },
  { name: "Victoria Falls",              iso: 716, wiki: "Victoria_Falls" },

  // Americas
  { name: "Christ the Redeemer",         iso:  76, wiki: "Christ_the_Redeemer_(statue)" },
  { name: "Iguazu Falls",                iso:  32, wiki: "Iguazu_Falls" },
  { name: "Statue of Liberty",           iso: 840, wiki: "Statue_of_Liberty" },
  { name: "Grand Canyon",                iso: 840, wiki: "Grand_Canyon" },
  { name: "Golden Gate Bridge",          iso: 840, wiki: "Golden_Gate_Bridge" },
  { name: "Chichen Itza",                iso: 484, wiki: "Chichen_Itza" },
  { name: "Machu Picchu",                iso: 604, wiki: "Machu_Picchu" },
  { name: "Easter Island Statues",       iso: 152, wiki: "Easter_Island" },
  { name: "Salar de Uyuni",              iso:  68, wiki: "Salar_de_Uyuni" },
  { name: "Angel Falls",                 iso: 862, wiki: "Angel_Falls" },
  { name: "CN Tower",                    iso: 124, wiki: "CN_Tower" },
  { name: "Tikal",                       iso: 320, wiki: "Tikal" },
  { name: "Walled City of Cartagena",    iso: 170, wiki: "Walled_City_of_Cartagena" },
  { name: "Old Havana",                  iso: 192, wiki: "Old_Havana" },
  { name: "Galápagos Islands",           iso: 218, wiki: "Galápagos_Islands" },

  // Oceania
  { name: "Sydney Opera House",          iso:  36, wiki: "Sydney_Opera_House" },
  { name: "Uluru",                       iso:  36, wiki: "Uluru" },
  { name: "Milford Sound",               iso: 554, wiki: "Milford_Sound" },
];

async function fetchThumbnail(wiki) {
  const url = `https://en.wikipedia.org/api/rest_v1/page/summary/${encodeURIComponent(wiki)}`;
  const res = await fetch(url, { headers: { 'User-Agent': 'GeoStreak/1.0 (https://github.com/BasEijs/geostreak)' } });
  if (!res.ok) return null;
  const data = await res.json();
  const src = data?.thumbnail?.source;
  if (!src) return null;
  // Upsize: replace the Npx- segment with 600px
  return src.replace(/\/\d+px-/, '/600px-');
}

async function main() {
  const results = [];
  const failed = [];

  for (const entry of SEED) {
    process.stdout.write(`Fetching: ${entry.name} ... `);
    const photo_url = await fetchThumbnail(entry.wiki);
    if (photo_url) {
      results.push({ name: entry.name, iso: entry.iso, photo_url });
      console.log('OK');
    } else {
      failed.push(entry);
      console.log('FAILED (no thumbnail)');
    }
    // Polite delay to avoid hammering Wikipedia
    await new Promise(r => setTimeout(r, 200));
  }

  const js = `// Auto-generated by scripts/fetch-landmark-photos.js — do not edit by hand
// Re-run the script to refresh photo URLs or add landmarks via the SEED array

const LANDMARKS = ${JSON.stringify(results, null, 2)};
`;

  writeFileSync(OUT, js, 'utf8');
  console.log(`\nWrote ${results.length} landmarks to ${OUT}`);

  if (failed.length) {
    console.log(`\nFailed (${failed.length}) — add these manually or fix the wiki slug:`);
    failed.forEach(e => console.log(`  iso:${e.iso}  wiki:"${e.wiki}"  name:"${e.name}"`));
  }
}

main().catch(err => { console.error(err); process.exit(1); });
