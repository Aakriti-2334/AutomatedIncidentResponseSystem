import requests

def generate_summary_from_llm(interval_minutes, packet_logs):
    """
    Generates a summary of recent network activity using an external LLM.

    Args:
        interval_minutes (int): The time interval in minutes to summarize (currently unused).
        packet_logs (list): A list of packet log dictionaries.

    Returns:
        str: The generated summary.
    """
    if not packet_logs:
        return "No significant network activity detected."

    # Format the data for the LLM prompt
    formatted_data = "Recent Network Activity:\n"
    for log in packet_logs:
        formatted_data += f"- IP: {log.get('details', {}).get('src_ip', 'N/A')}, Prediction: {log.get('attack_prediction', 'N/A')}, Action: {log.get('action', 'N/A')}\n"

    prompt = f"""
    Analyze the following network activity logs and provide a detailed textual summary.
    The summary should include:
    1. An overview of the detected activity.
    2. A breakdown of the types of predictions (e.g., how many 'Benign', 'DDoS', etc.).
    3. A list of the actions taken (e.g., 'Allow', 'Block').
    4. A concluding paragraph that assesses the overall security posture based on the logs.

    Logs:
    {formatted_data}
    """

    # This is a placeholder for the actual implementation of the LLM summary generation.
    # In a real-world scenario, this would involve making a request to the LLM API.
    # Example using a hypothetical Llama 2 API:
    """
    try:
        response = requests.post(
            "https://api.example.com/llama2/generate",
            json={
                "prompt": prompt,
                "max_tokens": 500
            },
            headers={"Authorization": "Bearer YOUR_API_KEY"}
        )
        response.raise_for_status()
        llm_summary = response.json().get("summary")
    except requests.exceptions.RequestException as e:
        print(f"Error calling LLM API: {e}")
        llm_summary = "Error generating summary from LLM."
    """

    # Mock summary for demonstration
    predictions = [log.get('attack_prediction', 'N/A') for log in packet_logs]
    actions = [log.get('action', 'N/A') for log in packet_logs]
    prediction_counts = {pred: predictions.count(pred) for pred in set(predictions)}
    action_counts = {act: actions.count(act) for act in set(actions)}

    llm_summary = "Detailed Network Activity Report\n\n"
    llm_summary += "Overview:\n"
    llm_summary += f"The system has processed {len(packet_logs)} packets. "
    llm_summary += "The activity includes a mix of benign and potentially malicious traffic, with corresponding actions taken by the system.\n\n"
    llm_summary += "Prediction Breakdown:\n"
    for pred, count in prediction_counts.items():
        llm_summary += f"- {pred}: {count}\n"
    llm_summary += "\nActions Taken:\n"
    for act, count in action_counts.items():
        llm_summary += f"- {act}: {count}\n"
    llm_summary += "\nConclusion:\n"
    if 'Block' in actions or 'Temporary Block' in actions:
        llm_summary += "The system has actively mitigated potential threats by blocking suspicious IP addresses. This indicates that the automated incident response is functioning as expected. However, the presence of malicious traffic warrants continued monitoring."
    else:
        llm_summary += "The network activity appears to be normal, with no major threats detected. The system is monitoring the traffic, and all connections have been allowed. The security posture is currently stable."

    return llm_summary

