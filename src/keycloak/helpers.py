def to_camel_case(snake_cased_str):
    components = snake_cased_str.split('_')
    # We capitalize the first letter of each component except the first one
    # with the 'title' method and join them together.
    return components[0] + ''.join(map(str.capitalize, components[1:]))
