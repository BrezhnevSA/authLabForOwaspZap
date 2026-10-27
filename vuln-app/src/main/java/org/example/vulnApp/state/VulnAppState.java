package org.example.vulnApp.state;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import org.example.vulnApp.model.SomeObject;
import org.springframework.stereotype.Component;

@Component
public class VulnAppState {
    private final Set<String> payloadSent = Collections.synchronizedSet(new HashSet<>());
    private final List<SomeObject> commentRepository = Collections.synchronizedList(new ArrayList<>());
    private final List<SomeObject> eventRepository = new CopyOnWriteArrayList<>();
    private final List<SomeObject> issueRepository = Collections.synchronizedList(new ArrayList<>());

    public Set<String> payloadSent() {
        return payloadSent;
    }

    public List<SomeObject> commentRepository() {
        return commentRepository;
    }

    public List<SomeObject> eventRepository() {
        return eventRepository;
    }

    public List<SomeObject> issueRepository() {
        return issueRepository;
    }

    public void clear() {
        commentRepository.clear();
        eventRepository.clear();
        payloadSent.clear();
        issueRepository.clear();
    }
}
