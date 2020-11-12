def ranges_of_list(input_list, ranges):
    output_list = []
    for start, end in ranges:
        if end == "end":
            output_list += input_list[start:]
        else:
            output_list += input_list[start:end]
    return output_list
