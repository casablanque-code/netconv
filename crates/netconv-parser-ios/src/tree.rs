/// Pass 1: строим дерево по отступам.
/// Не знаем семантику — просто структура.

#[derive(Debug, Clone)]
pub struct RawNode {
    pub line_num: usize,
    pub indent: usize,
    pub text: String,
    pub children: Vec<RawNode>,
}

impl RawNode {
    pub fn new(line_num: usize, indent: usize, text: &str) -> Self {
        RawNode {
            line_num,
            indent,
            text: text.to_string(),
            children: vec![],
        }
    }

    /// Первое слово — ключевое слово команды
    pub fn keyword(&self) -> &str {
        self.text.split_whitespace().next().unwrap_or("")
    }

    /// Все слова после первого
    pub fn args(&self) -> Vec<&str> {
        self.text.split_whitespace().skip(1).collect()
    }

    /// Полный текст без leading whitespace
    pub fn full(&self) -> &str {
        &self.text
    }
}

fn leading_spaces(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// Корень дерева — список top-level нод
#[derive(Debug)]
pub struct RawTree {
    pub nodes: Vec<RawNode>,
}

// ---------------------------------------------------------------------------
// Построение дерева через стек индексов (единственная используемая реализация —
// вызывается из IosParser::parse через parse_raw_tree)
// ---------------------------------------------------------------------------

pub fn parse_raw_tree(input: &str) -> RawTree {
    let mut all_nodes: Vec<RawNode> = vec![];

    for (line_num, line) in input.lines().enumerate() {
        let trimmed_end = line.trim_end();
        if trimmed_end.is_empty() {
            continue;
        }

        let stripped = trimmed_end.trim_start_matches('!');
        if stripped.trim().is_empty() || trimmed_end.trim_start().starts_with('!') {
            continue;
        }

        let indent = leading_spaces(trimmed_end);
        let text = trimmed_end.trim();

        all_nodes.push(RawNode::new(line_num + 1, indent, text));
    }

    // Строим дерево: ноды с indent > предыдущей становятся детьми
    build_tree_from_flat(all_nodes)
}

fn build_tree_from_flat(flat: Vec<RawNode>) -> RawTree {
    if flat.is_empty() {
        return RawTree { nodes: vec![] };
    }

    // Используем стек для отслеживания текущего пути в дереве
    // Элемент стека: (indent, index)
    // Строим дерево in-place через arena-like подход

    // Простой подход: рекурсивный через срезы
    let nodes = assemble(&flat, 0, 0).0;
    RawTree { nodes }
}

fn assemble(flat: &[RawNode], idx: usize, min_indent: usize) -> (Vec<RawNode>, usize) {
    let mut result: Vec<RawNode> = vec![];
    let mut i = idx;

    while i < flat.len() {
        let node = &flat[i];

        if node.indent < min_indent {
            break;
        }

        if node.indent > min_indent {
            // Это дочерний элемент — должен быть добавлен к последнему в result
            if let Some(parent) = result.last_mut() {
                let (children, consumed) = assemble(flat, i, node.indent);
                parent.children.extend(children);
                i += consumed;
            } else {
                // Нет родителя — берём как top-level (нестандартный конфиг)
                let mut orphan = flat[i].clone();
                orphan.children = vec![];
                result.push(orphan);
                i += 1;
            }
        } else {
            // indent == min_indent — sibling
            let mut new_node = flat[i].clone();
            new_node.children = vec![];
            result.push(new_node);
            i += 1;
        }
    }

    let consumed = i - idx;
    (result, consumed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_interface_block() {
        let input = r#"
hostname ROUTER-01
!
interface GigabitEthernet0/0
 description WAN
 ip address 10.0.0.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/1
 description LAN
 ip address 192.168.1.1 255.255.255.0
 shutdown
"#;
        let tree = parse_raw_tree(input);
        assert_eq!(tree.nodes.len(), 3); // hostname + 2 interfaces
        assert_eq!(tree.nodes[1].keyword(), "interface");
        assert_eq!(tree.nodes[1].children.len(), 3); // description, ip, no shutdown
    }
}
