<?php
class Template {
    private string $name;
    public function __construct(string $name) { $this->name = $name; }
    public function render(array $data): string {
        return strtr($this->loadFile(), $this->prepareKeys($data));
    }
    private function loadFile(): string {
        return file_get_contents(__DIR__ . "/templates/" . $this->name . ".html");
    }
    private function prepareKeys(array $data): array {
        $out = [];
        foreach ($data as $k => $v) $out["{{$k}}"] = htmlspecialchars((string)$v);
        return $out;
    }
}
