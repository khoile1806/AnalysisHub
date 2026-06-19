const syntaxHighlight = (json: any) => {
  if (typeof json !== 'string') {
    json = JSON.stringify(json, undefined, 2);
  }
  json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match: string) {
    let cls = 'text-blue-400';
    if (/^"/.test(match)) {
      if (/:$/.test(match)) {
        cls = 'text-emerald-400'; // Keys
      } else {
        cls = 'text-amber-300'; // Strings
      }
    } else if (/true|false/.test(match)) {
      cls = 'text-purple-400'; // Booleans
    } else if (/null/.test(match)) {
      cls = 'text-gray-500'; // Null
    } else {
      cls = 'text-orange-400'; // Numbers
    }
    return '<span class="' + cls + '">' + match + '</span>';
  });
}

export function JsonViewer({ data, className = '' }: { data: any, className?: string }) {
  const html = syntaxHighlight(data)
  return (
    <pre 
      className={`text-xs font-mono text-gray-300 whitespace-pre-wrap break-all bg-gray-950 p-3 rounded-lg border border-gray-800/60 overflow-x-auto ${className}`}
      dangerouslySetInnerHTML={{ __html: html }} 
    />
  )
}
