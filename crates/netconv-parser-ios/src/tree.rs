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

/// Корень дерева — список top-level нод
#[derive(Debug)]
pub struct RawTree {
    pub nodes: Vec<RawNode>,
}

impl RawTree {
    pub fn parse(input: &str) -> Self {
        let _roots: Vec<RawNode> = vec![];
        // стек: (indent, index в текущем родителе)
        // используем Vec<usize> — индексы в roots для корня,
        // но для вложенности нам нужен mutable стек
        // Проще: flat list + post-process в дерево через стек

        let lines: Vec<(usize, usize, &str)> = input
            .lines()
            .enumerate()
            .filter_map(|(i, line)| {
                let trimmed = line.trim_end();
                // Пропускаем пустые и комментарии
                if trimmed.is_empty() || trimmed.starts_with('!') {
                    return None;
                }
                let indent = leading_spaces(trimmed);
                let text = trimmed.trim();
                if text.is_empty() {
                    return None;
                }
                Some((i + 1, indent, text))
            })
            .collect();

        // Строим дерево итеративно через стек
        // stk хранит (indent_level, mutable_ref) — не работает с Rust borrow
        // Используем индексный подход: flat vec + parent indices

        let flat: Vec<(usize, usize, String)> = lines
            .iter()
            .map(|(ln, ind, txt)| (*ln, *ind, txt.to_string()))
            .collect();

        // Конвертируем flat list в дерево рекурсивно
        let tree = build_tree(&flat, 0, 0).0;

        RawTree { nodes: tree }
    }
}

fn leading_spaces(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// Рекурсивно строим дерево из flat списка.
/// Возвращает (nodes, consumed_count)
fn build_tree(
    flat: &[(usize, usize, String)],
    start: usize,
    parent_indent: usize,
) -> (Vec<RawNode>, usize) {
    let mut nodes = vec![];
    let mut i = start;

    while i < flat.len() {
        let (ln, indent, text) = &flat[i];

        // Если отступ меньше или равен родительскому — выходим
        if *indent <= parent_indent && start != 0 {
            break;
        }
        // На верхнем уровне (start==0) берём все indent==0
        if start == 0 && *indent > 0 {
            // это дочерний — должен быть добавлен к последнему root
            if let Some(_last) = nodes.last_mut() {
                let (_children, _consumed) = build_tree(flat, i, *indent - 1);
                // Нет, нужно добавлять к последней ноде
                // Перестроим: возвращаемся к итеративному подходу
                break;
            }
            break;
        }

        let mut node = RawNode::new(*ln, *indent, text);
        i += 1;

        // Собираем дочерние — всё что идёт дальше с большим отступом
        while i < flat.len() && flat[i].1 > *indent {
            let (children, consumed) = build_tree(flat, i, *indent);
            node.children.extend(children);
            i += consumed;
        }

        nodes.push(node);
    }

    let consumed = i - start;
    (nodes, consumed)
}

// ---------------------------------------------------------------------------
// Более надёжная реализация через стек индексов
// ---------------------------------------------------------------------------

pub fn parse_raw_tree(input: &str) -> RawTree {
    let mut all_nodes: Vec<RawNode> = vec![];

    for (line_num, line) in input.lines().enumerate() {
        let trimmed_end = line.trim_end();
        if trimmed_end.is_empty() { continue; }

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
